#!/usr/bin/env python3
import subprocess
import time
import csv
import io
import statistics
from typing import Dict, List, Tuple
import sys
import os

class ValkeyBenchmarkRunner:
    def __init__(self):
        self.test_configs = [
            {
                "name": "1. Module not loaded",
                "config": "valkey.conf.1",
                "user": None,
                "password": None
            },
            {
                "name": "2. Loaded but enabled=no", 
                "config": "valkey.conf.2",
                "user": None,
                "password": None
            },
            {
                "name": "3. User martin, no_audit=1, always_audit_config=no",
                "config": "valkey.conf.3", 
                "user": "martin",
                "password": "mpass"
            },
            {
                "name": "4. User martin, no_audit=1, always_audit_config=yes",
                "config": "valkey.conf.4",
                "user": "martin", 
                "password": "mpass"
            },
            {   
                "name": "5. User martin, events=all, always_audit_config=no",
                "config": "valkey.conf.5",
                "user": "martin", 
                "password": "mpass"
            }
        ]
        self.results = {}
    
    def start_server(self, config_file: str) -> subprocess.Popen:
        """Start valkey server with given config"""
        print(f"Starting server with {config_file}...")
        proc = subprocess.Popen(['valkey-server', config_file])
        time.sleep(5)  # Wait for server to start
        return proc
    
    def stop_server(self, proc: subprocess.Popen):
        """Stop valkey server"""
        print("Stopping server...")
        try:
            subprocess.run(['valkey-cli', '-p', '47885', 'shutdown'], 
                         timeout=10, capture_output=True)
        except subprocess.TimeoutExpired:
            print("Shutdown timeout, killing process...")
            proc.kill()
        
        proc.wait()
        time.sleep(2)  # Wait for cleanup
    
    def run_benchmark(self, user: str = None, password: str = None) -> Dict[str, float]:
        """Run valkey-benchmark and parse CSV output"""
        cmd = [
            'valkey-benchmark', 
            '-p', '47885',
            '-t', 'set,get',
            '-d', '100', 
            '-c', '1',
            #'-n', '100000',
            #'-n', '100',
            '--csv'
        ]
        
        if user and password:
            cmd.extend(['--user', user, '-a', password])
        
        print(f"Running benchmark: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                print(f"Benchmark failed: {result.stderr}")
                return {}
            
            return self.parse_csv_output(result.stdout)
        
        except subprocess.TimeoutExpired:
            print("Benchmark timeout!")
            return {}
    
    def parse_csv_output(self, csv_output: str) -> Dict[str, float]:
        """Parse CSV output from valkey-benchmark"""
        results = {}
        reader = csv.DictReader(io.StringIO(csv_output))
        
        for row in reader:
            test_name = row['test']
            print(f"testname: {test_name}")
            rps = float(row['rps'])
            avg_latency = float(row['avg_latency_ms'])
            min_latency = float(row['min_latency_ms']) 
            p50_latency = float(row['p50_latency_ms'])
            p95_latency = float(row['p95_latency_ms'])
            p99_latency = float(row['p99_latency_ms'])
            max_latency = float(row['max_latency_ms'])
            
            results[test_name] = {
                'rps': rps,
                'avg_latency_ms': avg_latency,
                'min_latency_ms': min_latency,
                'p50_latency_ms': p50_latency, 
                'p95_latency_ms': p95_latency,
                'p99_latency_ms': p99_latency,
                'max_latency_ms': max_latency
            }
        
        return results
    
    def run_test_iterations(self, config: Dict, iterations: int = 3) -> Dict:
        """Run a test configuration multiple times"""
        print(f"\n{'='*60}")
        print(f"Running test: {config['name']}")
        print(f"Iterations: {iterations}")
        print(f"{'='*60}")
        
        all_results = {'SET': [], 'GET': []}
        
        for i in range(iterations):
            print(f"\nIteration {i+1}/{iterations}")
            
            # Start server
            server_proc = self.start_server(config['config'])
            
            try:
                # Run benchmark
                benchmark_results = self.run_benchmark(
                    config.get('user'), 
                    config.get('password')
                )
                
                if benchmark_results:
                    for test_type in ['SET', 'GET']:
                        if test_type in benchmark_results:
                            all_results[test_type].append(benchmark_results[test_type])
                            print(f"  {test_type}: {benchmark_results[test_type]['rps']:.2f} rps, "
                                  f"{benchmark_results[test_type]['avg_latency_ms']:.3f}ms avg")
                else:
                    print(f"  Iteration {i+1} failed!")
            
            finally:
                # Stop server
                self.stop_server(server_proc)
        
        return all_results
    
    def calculate_statistics(self, results: List[Dict]) -> Dict:
        """Calculate mean, std dev, min, max for each metric"""
        if not results:
            return {}
        
        metrics = results[0].keys()
        stats = {}
        
        for metric in metrics:
            values = [r[metric] for r in results]
            stats[metric] = {
                'mean': statistics.mean(values),
                'stdev': statistics.stdev(values) if len(values) > 1 else 0,
                'min': min(values),
                'max': max(values),
                'values': values
            }
        
        return stats
    
    def print_summary(self):
        """Print formatted summary of all results"""
        print(f"\n{'='*80}")
        print("PERFORMANCE SUMMARY")
        print(f"{'='*80}")
        
        for config_name, test_results in self.results.items():
            print(f"\n{config_name}")
            print("-" * len(config_name))
            
            for test_type in ['SET', 'GET']:
                if test_type in test_results and test_results[test_type]:
                    stats = self.calculate_statistics(test_results[test_type])
                    
                    print(f"\n{test_type} Operations:")
                    print(f"  RPS:          {stats['rps']['mean']:8.2f} ± {stats['rps']['stdev']:6.2f} "
                          f"({stats['rps']['min']:8.2f} - {stats['rps']['max']:8.2f})")
                    print(f"  Avg Latency:  {stats['avg_latency_ms']['mean']:8.3f} ± {stats['avg_latency_ms']['stdev']:6.3f} ms "
                          f"({stats['avg_latency_ms']['min']:8.3f} - {stats['avg_latency_ms']['max']:8.3f})")
                    print(f"  P50 Latency:  {stats['p50_latency_ms']['mean']:8.3f} ± {stats['p50_latency_ms']['stdev']:6.3f} ms")
                    print(f"  P95 Latency:  {stats['p95_latency_ms']['mean']:8.3f} ± {stats['p95_latency_ms']['stdev']:6.3f} ms")
                    print(f"  P99 Latency:  {stats['p99_latency_ms']['mean']:8.3f} ± {stats['p99_latency_ms']['stdev']:6.3f} ms")
                    print(f"  Max Latency:  {stats['max_latency_ms']['mean']:8.3f} ± {stats['max_latency_ms']['stdev']:6.3f} ms")
    
    def print_comparison_table(self):
        """Print comparison table showing relative performance"""
        print(f"\n{'='*80}")
        print("PERFORMANCE COMPARISON (% of baseline)")
        print(f"{'='*80}")
        
        # Find configuration starting with "1" as baseline
        baseline_name = None
        for config_name in self.results.keys():
            if config_name.strip().startswith('1.'):
                baseline_name = config_name
                break
        
        if baseline_name is None:
            baseline_name = list(self.results.keys())[0]
        
        print(f"Using '{baseline_name}' as baseline\n")
        baseline_results = self.results[baseline_name]
        
        header = f"{'Configuration':<40} {'SET RPS':<10} {'GET RPS':<10} {'SET Avg':<10} {'GET Avg':<10}"
        print(header)
        print("-" * len(header))
        
        for config_name, test_results in self.results.items():
            row = f"{config_name[:39]:<40}"
            
            # Calculate all metrics first
            set_rps_ratio = 0
            set_latency_ratio = 0 
            get_rps_ratio = 0
            get_latency_ratio = 0
            
            # SET calculations
            if ('SET' in test_results and test_results['SET'] and
                'SET' in baseline_results and baseline_results['SET']):
                
                current_stats = self.calculate_statistics(test_results['SET'])
                baseline_stats = self.calculate_statistics(baseline_results['SET'])
                
                if 'rps' in current_stats and 'rps' in baseline_stats:
                    set_rps_ratio = (current_stats['rps']['mean'] / baseline_stats['rps']['mean']) * 100
                    
                if 'avg_latency_ms' in current_stats and 'avg_latency_ms' in baseline_stats:
                    set_latency_ratio = (current_stats['avg_latency_ms']['mean'] / baseline_stats['avg_latency_ms']['mean']) * 100
            
            # GET calculations  
            if ('GET' in test_results and test_results['GET'] and
                'GET' in baseline_results and baseline_results['GET']):
                
                current_stats = self.calculate_statistics(test_results['GET'])
                baseline_stats = self.calculate_statistics(baseline_results['GET'])
                
                if 'rps' in current_stats and 'rps' in baseline_stats:
                    get_rps_ratio = (current_stats['rps']['mean'] / baseline_stats['rps']['mean']) * 100
                    
                if 'avg_latency_ms' in current_stats and 'avg_latency_ms' in baseline_stats:
                    get_latency_ratio = (current_stats['avg_latency_ms']['mean'] / baseline_stats['avg_latency_ms']['mean']) * 100
            
            # Format output with consistent spacing
            if set_rps_ratio > 0:
                row += f"{set_rps_ratio:8.1f}%  "
            else:
                row += "    N/A    "
                
            if get_rps_ratio > 0:
                row += f"{get_rps_ratio:8.1f}%  "
            else:
                row += "    N/A    "
                
            if set_latency_ratio > 0:
                row += f"{set_latency_ratio:8.1f}%  "
            else:
                row += "    N/A    "
                
            if get_latency_ratio > 0:
                row += f"{get_latency_ratio:8.1f}%"
            else:
                row += "    N/A"
            
            print(row)

    def run_all_tests(self, iterations: int = 3):
        """Run all test configurations"""
        print("Starting Valkey Performance Test Suite")
        print(f"Iterations per test: {iterations}")
        
        for config in self.test_configs:
            self.results[config['name']] = self.run_test_iterations(config, iterations)
        
        self.print_summary()
        self.print_comparison_table()

def createifnotexists_directory(directory_path):
    """
    Checks if a directory exists at the given path. If it does not,
    create it including any necessary parent directories.
    """
    if not os.path.exists(directory_path):
        print(f"Directory '{directory_path}' does not exist. Creating it...")
        try:
            os.makedirs(directory_path)
            print(f"Directory '{directory_path}' created successfully.")
        except OSError as error:
            print(f"Error: Could not create directory '{directory_path}'.")
            print(f"Reason: {error}")
    else:
        print(f"Directory '{directory_path}' already exists.")

def main():
    auditdir = '/tmp/vkaperf'
    createifnotexists_directory(auditdir)

    runner = ValkeyBenchmarkRunner()
    
    # Check if iterations specified as command line argument
    iterations = 3
    if len(sys.argv) > 1:
        try:
            iterations = int(sys.argv[1])
        except ValueError:
            print(f"Invalid iterations value: {sys.argv[1]}, using default: 3")
    
    runner.run_all_tests(iterations)

if __name__ == "__main__":
    main()
