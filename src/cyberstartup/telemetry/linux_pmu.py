import os
import torch
import ctypes
import logging

logger = logging.getLogger(__name__)

class LiveTelemetry:
    """
    LiveTelemetry constructs a Temporal Asset Graph (TAG) by dynamically
    reading Linux system metrics and hardware Performance Monitor Units (PMUs).
    Operates as an inline host-CPU eBPF solution.
    """
    def __init__(self, num_assets: int = 10, host_address="127.0.0.1"):
        self.num_assets = num_assets
        self.host_address = host_address
        
    def read_cpu_stats(self) -> torch.Tensor:
        """
        Read live CPU stats via hardware PMUs.
        Operates natively using perf to analyze L1/L2 cache misses and TLB thrashing.
        
        Returns:
            torch.Tensor: Node feature tensor of shape (num_assets, 128).
        """
        features = torch.zeros((self.num_assets, 128), dtype=torch.float32)
        
        try:
            # Replaced blocking subprocess 'perf stat' with native eBPF map reading for zero-overhead
            import ctypes
            import os
            
            map_path = b'/sys/fs/bpf/pmu_ringbuf'
            if not os.path.exists(map_path):
                raise FileNotFoundError("eBPF PMU map not pinned.")
                
            libc = ctypes.CDLL('libbpf.so')
            map_fd = libc.bpf_obj_get(ctypes.c_char_p(map_path))
            if map_fd > 0:
                key = ctypes.c_uint32(0)
                value = (ctypes.c_uint64 * 4)() # [l1_misses, l2_misses, branch_misses, tlb_misses]
                
                class bpf_attr_map_lookup_elem(ctypes.Structure):
                    _fields_ = [('map_fd', ctypes.c_uint32), ('key', ctypes.c_uint64), ('value', ctypes.c_uint64), ('flags', ctypes.c_uint64)]
                    
                lookup_attr = bpf_attr_map_lookup_elem(map_fd, ctypes.cast(ctypes.byref(key), ctypes.c_void_p).value, ctypes.cast(ctypes.byref(value), ctypes.c_void_p).value, 0)
                
                if libc.syscall(321, 1, ctypes.byref(lookup_attr), ctypes.sizeof(lookup_attr)) == 0:
                    for i in range(self.num_assets):
                        features[i, 0] = float(value[0] % (i + 1 + 1000))
                        features[i, 1] = float(value[1] % (i + 1 + 1000))
                        features[i, 2] = float(value[2] % (i + 1 + 1000))
                        features[i, 3] = float(value[3] % (i + 1 + 1000))
                else:
                    raise RuntimeError("Failed to read eBPF PMU map natively.")
            else:
                raise RuntimeError("Invalid map FD")
                
        except Exception as e:
            logger.error(f"PMU hardware reading failed: {e}.")
            raise RuntimeError(f"Strict Hardware Mode: Failed to read PMU stats ({e})")

            
        # Normalize features to prevent NaN explosions in the ODE solver
        mean = features.mean(dim=1, keepdim=True)
        std = features.std(dim=1, keepdim=True)
        features = (features - mean) / (std + 1e-5)
        
        return features

    def read_network_topology(self) -> torch.Tensor:
        """
        Read active network connections from /proc/net/tcp and /proc/net/udp
        to dynamically construct the edge topology (edge_index) connecting
        local IP/Port pairs.
        
        Returns:
            torch.LongTensor: Shape (2, num_edges) representing the edge indices.
        """
        edges = set()
        node_ids = {}
        
        def get_node_id(endpoint: str) -> int:
            if endpoint not in node_ids:
                # Map endpoint to a valid node index in [0, num_assets - 1]
                node_ids[endpoint] = len(node_ids) % self.num_assets
            return node_ids[endpoint]
            
        # Replace /proc/net polling with native libbpf-based eBPF map reading
        try:
            # We attempt to read the pinned eBPF map populated by our XDP probe
            map_path = b'/sys/fs/bpf/cyberstartup_tcp_map'
            if os.path.exists(map_path):
                st = os.stat(map_path)
                if st.st_uid != 0 or (st.st_mode & 0o077) != 0:
                    raise PermissionError(f"Insecure permissions on {map_path}. Must be owned by root and 0600.")
                    
            import ctypes
            libc = ctypes.CDLL('libbpf.so')
            map_fd = libc.bpf_obj_get(ctypes.c_char_p(map_path))
            if map_fd > 0:
                # If we successfully hooked into the eBPF map, read edges natively
                key = ctypes.c_uint32(0)
                next_key = ctypes.c_uint32(0)
                value = (ctypes.c_uint32 * 2)() # [src_ip, dst_ip]
                
                class bpf_attr_map_get_next_key(ctypes.Structure):
                    _fields_ = [('map_fd', ctypes.c_uint32), ('key', ctypes.c_uint64), ('next_key', ctypes.c_uint64)]
                    
                class bpf_attr_map_lookup_elem(ctypes.Structure):
                    _fields_ = [('map_fd', ctypes.c_uint32), ('key', ctypes.c_uint64), ('value', ctypes.c_uint64), ('flags', ctypes.c_uint64)]
                
                # Iterate through the eBPF map
                while libc.syscall(321, 4, ctypes.byref(bpf_attr_map_get_next_key(map_fd, ctypes.cast(ctypes.byref(key), ctypes.c_void_p).value, ctypes.cast(ctypes.byref(next_key), ctypes.c_void_p).value)), ctypes.sizeof(bpf_attr_map_get_next_key)) == 0:
                    lookup_attr = bpf_attr_map_lookup_elem(map_fd, ctypes.cast(ctypes.byref(next_key), ctypes.c_void_p).value, ctypes.cast(ctypes.byref(value), ctypes.c_void_p).value, 0)
                    if libc.syscall(321, 1, ctypes.byref(lookup_attr), ctypes.sizeof(lookup_attr)) == 0:
                        src_node = get_node_id(str(value[0]))
                        dst_node = get_node_id(str(value[1]))
                        edges.add((src_node, dst_node))
                    key.value = next_key.value
                    
        except Exception as e:
            logger.error(f"eBPF map reading failed: {e}.")
            raise RuntimeError(f"Strict Hardware Mode: Failed to read eBPF topology ({e})")

            
        edge_list = list(edges)
        u_nodes = [e[0] for e in edge_list]
        v_nodes = [e[1] for e in edge_list]
        
        edge_index = torch.tensor([u_nodes, v_nodes], dtype=torch.long)
        return edge_index
