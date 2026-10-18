#cn assignment 2 (gbn vs sr) 24K-0789
import argparse, csv, heapq, itertools, random, time, zlib,sys
from pathlib import Path

class Frame: #initializes a frame with its type, internal packet ID, sequence number, payload, and checksum.
    def __init__(self, kind, packet_id, seq, payload=""):
        self.kind, self.packet_id, self.seq, self.payload = kind, packet_id, seq, payload
        self.checksum = self.calc() 

    def calc(self):
        return zlib.crc32(f"{self.kind}|{self.seq}|{self.payload}".encode()) #calculates checksum(crc32 algo) from frame type, seq num, payload
    
    def valid(self):
        return self.checksum == self.calc() #checksum validation when frame arrives and checks it with the orignal checksum

class Channel: #the channel simulates the network between the sender and receiver.
    def __init__(self, sim): self.sim = sim
    
    def send(self, frame, now):
        s = self.sim
        is_ack = frame.kind == "ACK"
        label = f"ACK seq={frame.seq} (ack_id={frame.packet_id})" if is_ack else f"data pkt={frame.packet_id} seq={frame.seq}"
        if s.rng.random() < s.loss:
            s.stats["lost_acks" if is_ack else "lost_data"] += 1
            s.log(f"CHANNEL LOSS: {label}"); return
        f = Frame(frame.kind, frame.packet_id, frame.seq, frame.payload)
        if s.rng.random() < s.corruption: #compares random value(bw 0.0 and 1.0) with corruption probability to simulate corrupt packet 
            s.stats["corrupted_acks" if is_ack else "corrupted_data"] += 1
            # Alter a protected field without updating its checksum.
            f.payload += "#CORRUPT" if not is_ack else ""
            if is_ack: f.seq = (f.seq + 1) % s.modulus
            s.log(f"CHANNEL CORRUPTION: {label}")
        arrival = now + s.one_way_delay
        if s.rng.random() < s.delay: #compares random value(bw 0.0 and 1.0) with delay probability to simulate network delay 
            arrival += s.extra_delay
            s.stats["delayed_acks" if is_ack else "delayed_data"] += 1
            s.log(f"CHANNEL DELAY: {label}; arrival={arrival:.3f}")
        s.schedule(arrival, "ack" if is_ack else "data", f)

class Simulator:# Initializes the simulation parameters, protocol state, event queue, timers, and statistics.
    def __init__(self, protocol, packets=200, window=4, bits=3, loss=0, corruption=0,
                 delay=0, timeout=0.8, seed=789, verbose=True):
        self.protocol = protocol.lower()
        if self.protocol not in ("gbn", "sr"): raise ValueError("protocol must be gbn or sr")
        if packets < 1 or window < 1 or bits < 1: raise ValueError("packets/window/bits must be positive")
        self.total, self.window, self.bits = packets, window, bits
        self.modulus = 2**bits
        if self.protocol == "sr" and window > self.modulus//2:
            raise ValueError(f"SR window must be <= {self.modulus//2} for {bits}-bit sequence numbers")
        if self.protocol == "gbn" and window >= self.modulus:
            raise ValueError(f"GBN window must be < {self.modulus} for {bits}-bit sequence numbers")
        for name, p in (("loss",loss),("corruption",corruption),("delay",delay)):
            if not 0 <= p <= 1: raise ValueError(f"{name} must be between 0 and 1")
        if timeout <= 0: raise ValueError("timeout must be positive")
        self.loss, self.corruption, self.delay, self.timeout = loss, corruption, delay, timeout
        self.rng, self.verbose = random.Random(seed), verbose
        self.one_way_delay, self.extra_delay = 0.25, 1.0
        self.events, self.counter, self.now = [], itertools.count(), 0.0
        self.base = self.nextseqnum = 0 #base=sender oldest unacknowledged packet, nextseqnum=ID of the next packet to send
        self.expectedseqnum = self.rcv_base = 0 #expectedseqnum=next packet ID of expected packet (for gbn), rcv_base=first packet ID not received in order(for SR) 
        self.acked = [False]*packets
        self.buffer = {} #stores out of order SR packets
        self.delivered = []
        self.timer_generation = 0
        self.sr_timer_generation = {}
        self.channel = Channel(self)
        self.stats = {k:0 for k in ["data_transmissions","retransmissions","ack_transmissions","lost_data","lost_acks","corrupted_data","corrupted_acks","delayed_data","delayed_acks","timeouts","checksum_rejections","out_of_order_discards"]}
    
    def log(self, msg):
        if self.verbose: print(f"{self.now:8.3f} {msg}")
    
    def schedule(self, when, kind, obj): heapq.heappush(self.events,(when,next(self.counter),kind,obj))

    #creates a data frame using the packet ID, its modulo sequence number, and a simulated payload.
    def data_frame(self, pid): return Frame("DATA",pid,pid%self.modulus,f"rescue-payload-{pid}") #(seq num = pid % self.modulus)
    
    def ack_frame(self, ack_id): return Frame("ACK",ack_id,ack_id%self.modulus)
    
    def start_gbn_timer(self):
        self.timer_generation += 1
        if self.base < self.nextseqnum:
            self.schedule(self.now+self.timeout,"gbn_timeout",(self.base,self.timer_generation))
    
    def start_sr_timer(self,pid):
        gen=self.sr_timer_generation.get(pid,0)+1; self.sr_timer_generation[pid]=gen
        self.schedule(self.now+self.timeout,"sr_timeout",(pid,gen))
    
    def send_data(self,pid,retrans=False):
        f=self.data_frame(pid); self.stats["data_transmissions"]+=1
        if retrans:
            self.stats["retransmissions"]+=1; self.log(f"RETRANSMIT pkt {pid} seq={f.seq}")
        else: self.log(f"SEND pkt {pid} seq={f.seq}")
        self.channel.send(f,self.now)
        if self.protocol=="sr": self.start_sr_timer(pid)
    
    def fill_window(self):
        while self.nextseqnum < self.total and self.nextseqnum < self.base+self.window:
            pid=self.nextseqnum; self.nextseqnum+=1
            was_empty=(self.base==pid)
            self.send_data(pid)
            if self.protocol=="gbn" and was_empty: self.start_gbn_timer()
    
    def send_ack(self,ack_id,kind="cumulative"):
        f=self.ack_frame(ack_id); self.stats["ack_transmissions"]+=1
        self.log(f"SEND {kind} ACK seq={f.seq} (internal next/id={ack_id})")
        self.channel.send(f,self.now)
    
    def receive_data(self,f):
        if not f.valid(): #checksum validation, if invalid packet discarded 
            self.stats["checksum_rejections"]+=1; self.log(f"RECEIVE pkt {f.packet_id}: checksum FAILED; discard")
            if self.protocol=="gbn": self.send_ack(self.expectedseqnum,"duplicate cumulative")
            return
        pid=f.packet_id
        self.log(f"RECEIVE valid pkt {pid} seq={f.seq}")
        if self.protocol=="gbn":
            if pid==self.expectedseqnum and f.seq==self.expectedseqnum%self.modulus:
                self.delivered.append(pid); self.expectedseqnum+=1
                self.log(f"DELIVER pkt {pid}; expectedseqnum={self.expectedseqnum}")
                self.send_ack(self.expectedseqnum) #if correctly received, ACK sent
            else:
                self.stats["out_of_order_discards"]+=1
                self.log(f"DISCARD out-of-order/duplicate pkt {pid}; expectedseqnum={self.expectedseqnum}")
                self.send_ack(self.expectedseqnum,"duplicate cumulative")
        else:
            # Receiver window uses rcv_base and the modulo sequence field; packet_id is
            # internal event bookkeeping, not a wire sequence number.
            in_window = self.rcv_base <= pid < self.rcv_base+self.window and f.seq==pid%self.modulus
            if in_window:
                if pid not in self.buffer and pid not in self.delivered:
                    self.buffer[pid]=f; self.log(f"BUFFER pkt {pid}; rcv_base={self.rcv_base}")
                self.send_ack(pid,"individual")
                while self.rcv_base in self.buffer:
                    self.buffer.pop(self.rcv_base)
                    self.delivered.append(self.rcv_base)
                    self.log(f"DELIVER pkt {self.rcv_base} in order")
                    self.rcv_base+=1
                self.log(f"RECEIVER WINDOW=[{self.rcv_base},{self.rcv_base+self.window-1}]")
            elif pid < self.rcv_base:
                self.stats["out_of_order_discards"]+=1
                self.log(f"DUPLICATE pkt {pid}; resend individual ACK")
                self.send_ack(pid,"individual duplicate") #ACK send if packet is in window and seq num matches
            else:
                self.stats["out_of_order_discards"]+=1
                self.log(f"DISCARD pkt {pid}; outside SR receiver window")
    
    def receive_ack(self,f): #verfies incoming ack and update sender window accordingly 
        if not f.valid():
            self.stats["checksum_rejections"]+=1; self.log(f"RECEIVE ACK seq={f.seq}: checksum FAILED; ignore"); return
        self.log(f"RECEIVE valid ACK seq={f.seq} (internal id={f.packet_id})")
        if self.protocol=="gbn":
            new_base=min(max(f.packet_id,self.base),self.nextseqnum)
            if new_base>self.base:
                old=self.base; self.base=new_base
                self.log(f"GBN sender window moves base {old}->{self.base}; nextseqnum={self.nextseqnum}")
                self.start_gbn_timer(); self.fill_window()
        else:
            pid=f.packet_id
            if self.base<=pid<self.nextseqnum and not self.acked[pid]:
                self.acked[pid]=True; self.log(f"SR marks pkt {pid} ACKED")
                old=self.base
                while self.base<self.total and self.acked[self.base]: self.base+=1
                if self.base!=old:
                    self.log(f"SR sender window moves base {old}->{self.base}; nextseqnum={self.nextseqnum}")
                    self.fill_window()

    #timeout fot both methods
    def gbn_timeout(self,payload):
        #key GBN behavior: one timeout can cause multiple retransmissions 
        pid,gen=payload
        if gen!=self.timer_generation or pid!=self.base or self.base>=self.nextseqnum: return
        self.stats["timeouts"]+=1; self.log(f"TIMEOUT oldest unACKed pkt {self.base}; resend all outstanding")
        for p in range(self.base,self.nextseqnum): self.send_data(p,True) #resends from base to nextseqnum
        self.start_gbn_timer()
    
    def sr_timeout(self,payload):
        pid,gen=payload
        if gen!=self.sr_timer_generation.get(pid) or pid<self.base or pid>=self.nextseqnum or self.acked[pid]: return
        self.stats["timeouts"]+=1; self.log(f"TIMEOUT pkt {pid}; selectively resend this packet")
        self.send_data(pid,True) #only resends the packet that timed out
    
    def run(self):
        wall=time.perf_counter(); self.fill_window(); count=0
        while len(self.delivered)<self.total:
            if not self.events: raise RuntimeError("Simulation stalled before all packets were delivered")
            when,_,kind,obj=heapq.heappop(self.events); self.now=when; count+=1
            if count>2_000_000: raise RuntimeError("Event limit reached; try a lower error probability or longer timeout")
            if kind=="data": self.receive_data(obj)
            elif kind=="ack": self.receive_ack(obj)
            elif kind=="gbn_timeout": self.gbn_timeout(obj)
            elif kind=="sr_timeout": self.sr_timeout(obj)
        elapsed=time.perf_counter()-wall
        self.log(f"COMPLETE: {len(self.delivered)}/{self.total} unique packets delivered")
        return {"protocol":self.protocol.upper(),"packets":self.total,"window":self.window,"bits":self.bits,
                
            "data_transmissions":self.stats["data_transmissions"], #data_transmissions: total data-frame sends, including retransmissions. 
            "retransmissions":self.stats["retransmissions"], #retransmissions: sends that were retransmissions.
            "ack_transmissions":self.stats["ack_transmissions"], #total count of ACKs trasmitted by receiver including duplicates
            "delivered":len(self.delivered), #delivered: number of packets delivered
            "simulated_time_s":round(self.now,4), #simulated_time_s: time elapsed according to the simulated network clock
            "throughput_packets_s":round(len(self.delivered)/self.now,4) if self.now else 0, #throughput_packets_s: delivered packets divided by simulated time.
            "execution_time_s":round(elapsed,6),"timeouts":self.stats["timeouts"],**self.stats} #execution_time_s: actual computer time spent running the simulation.


def run_experiments(seed=789, verbose=False): #present experiments configurations
    cases=[("A_Reliable",0,0,0),("B_Loss",0.10,0,0),("C_Mixed",0.05,0.05,0.10)]
    rows=[]
    for ci,(name,loss,corr,delay) in enumerate(cases):
        for pi,proto in enumerate(("gbn","sr")):
            run_seed=seed #+ci*100+pi
            sim=Simulator(proto,200,4,3,loss,corr,delay,0.8,run_seed,verbose)
            row=sim.run(); row.update(experiment=name,seed=run_seed,loss_probability=loss,corruption_probability=corr,delay_probability=delay)
            rows.append(row)
    return rows

def save_csv(rows,path):
    cols=["experiment","protocol","seed","packets","window","bits","loss_probability","corruption_probability","delay_probability","data_transmissions","retransmissions","ack_transmissions","delivered","simulated_time_s","throughput_packets_s","execution_time_s","timeouts","lost_data","lost_acks","corrupted_data","corrupted_acks","delayed_data","delayed_acks","checksum_rejections","out_of_order_discards"]
    with open(path,"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader(); w.writerows(rows)

def print_table(rows):
    print("\nExperiment     Protocol  Data tx  Retrans.  Delivered  Sim time(s)  Throughput(pkt/s)")
    print("-"*83)
    for r in rows: print(f"{r['experiment']:<14} {r['protocol']:<8} {r['data_transmissions']:>7} {r['retransmissions']:>10} {r['delivered']:>10} {r['simulated_time_s']:>12} {r['throughput_packets_s']:>18}")


def ask_int(prompt, default, minimum=1):
    while True:
        value = input(f"{prompt} [{default}]: ").strip()
        try:
            value = int(value) if value else default
            if value < minimum:
                print(f"Please enter a value >= {minimum}.")
                continue
            return value
        except ValueError:
            print("Please enter a valid integer.")


def ask_float(prompt, default, minimum=0.0, maximum=1.0):
    while True:
        value = input(f"{prompt} [{default}]: ").strip()
        try:
            value = float(value) if value else default
            if not minimum <= value <= maximum:
                print(f"Please enter a value between {minimum} and {maximum}.")
                continue
            return value
        except ValueError:
            print("Please enter a valid number.")


def ask_yes_no(prompt, default="n"):
    while True:
        value = input(f"{prompt} (y/n) [{default}]: ").strip().lower()
        if not value:
            value = default
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False
        print("Please enter y or n.")


def main():
    # No command-line arguments means interactive mode.
    if len(sys.argv) == 1:
        print("\n======================================")
        print(" CS3001 Assignment 2: GBN and SR")
        print("======================================")

        experiments = ask_yes_no(
            "Run all Task 4 experiments?", "n"
        )

        seed = ask_int("Random seed", 789)
        output_dir = input("Output directory [.]: ").strip() or "."

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

            
        if experiments:
            print("\n" + "=" * 45)
            print("PRESET EXPERIMENT PARAMETERS")
            print("=" * 45)

            cases = [
                ("A: Reliable", 0.0, 0.0, 0.0),
                ("B: Packet Loss", 0.10, 0.0, 0.0),
                ("C: Mixed Errors", 0.05, 0.05, 0.10)
            ]

            for name, loss, corruption, delay in cases:
                print(f"\nExperiment: {name}")
                print("  Packets:                 200")
                print("  Window size:             4")
                print("  Sequence number bits:    3")
                print(f"  Packet loss probability: {loss:.2f} ({loss * 100:.0f}%)")
                print(f"  Corruption probability:  {corruption:.2f} ({corruption * 100:.0f}%)")
                print(f"  Extra delay probability: {delay:.2f} ({delay * 100:.0f}%)")
                print("  Timeout:                 0.8 seconds")
                print("  Protocols:               GBN, SR")
                print(f"  Random seed:             {seed}")

            print("\n" + "=" * 45)
            print("RUNNING PRESET EXPERIMENTS")
            print("=" * 45)

            rows = run_experiments(seed, verbose=False)
            save_csv(rows, out / "results.csv")

            print_table(rows)
            print(f"\nResults saved to {out / 'results.csv'}")
            return


        print("\nEnter simulation parameters.")
        print("Press Enter to use each default value.")

        #inputs of custom parameters for the simulation
        while True:
            protocol = input("Protocol: GBN or SR [GBN]: ").strip().lower()
            if not protocol:
                protocol = "gbn"
            if protocol in ("gbn", "sr"):
                break
            print("Please enter GBN or SR.")

        packets = ask_int("Number of packets", 200)
        window = ask_int("Window size", 4)
        bits = ask_int("Sequence number bits", 3)

        loss = ask_float("Packet loss probability", 0.0)
        corruption = ask_float("Corruption probability", 0.0)
        delay = ask_float("Extra delay probability", 0.0)
        timeout = ask_float("Timeout in seconds", 0.8, 0.000001, float("inf"))

        verbose = ask_yes_no("Show detailed event logs?", "y")

        try:
            sim = Simulator(
                protocol=protocol,
                packets=packets,
                window=window,
                bits=bits,
                loss=loss,
                corruption=corruption,
                delay=delay,
                timeout=timeout,
                seed=seed,
                verbose=verbose
            )

            result = sim.run()

            print("\n========== SUMMARY ==========")
            for key, value in result.items():
                print(f"{key}: {value}")

        except ValueError as error:
            print(f"\nInvalid parameters: {error}")
            print("Run the program again and enter valid parameters.")

        return

    # Original command-line mode remains available.
    p = argparse.ArgumentParser(
        description="GBN/SR reliable-transfer simulator for CS3001 A2"
    )
    p.add_argument("--protocol", choices=["gbn", "sr"], default="gbn")
    p.add_argument("--packets", type=int, default=200)
    p.add_argument("--window", type=int, default=4)
    p.add_argument("--bits", type=int, default=3)
    p.add_argument("--loss", type=float, default=0)
    p.add_argument("--corruption", type=float, default=0)
    p.add_argument("--delay", type=float, default=0)
    p.add_argument("--timeout", type=float, default=0.8)
    p.add_argument("--seed", type=int, default=789)
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--experiments", action="store_true")
    p.add_argument("--output-dir", default=".")

    a = p.parse_args()
    out = Path(a.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if a.experiments:
        rows = run_experiments(a.seed, not a.quiet)
        save_csv(rows, out / "results.csv")
        print_table(rows)
        print(f"\nSaved {out / 'results.csv'}")
    else:
        sim = Simulator(
            a.protocol, a.packets, a.window, a.bits,
            a.loss, a.corruption, a.delay, a.timeout,
            a.seed, not a.quiet
        )
        result = sim.run()

        print("\nSUMMARY")
        for key, value in result.items():
            print(f"{key}: {value}")


if __name__ == "__main__":
    main()
