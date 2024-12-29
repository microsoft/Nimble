import time
from concurrent.futures import ThreadPoolExecutor
import pydoop.hdfs as hdfs

# Configuration
NR_FILES = 500000
NR_THREADS = 64
NR_FILES_PER_DIR = 4
BASE_DIR = "/benchmark_test"

# Utility functions for Hadoop operations
def create_file(file_path):
    with hdfs.open(file_path, 'w') as f:
        f.write("test data")

def mkdir(dir_path):
    hdfs.mkdir(dir_path)

def open_file(file_path):
    with hdfs.open(file_path, 'r') as f:
        f.read()

def delete(file_path):
    hdfs.rm(file_path, recursive=True)

def file_status(file_path):
    return hdfs.stat(file_path)

def rename(src_path, dest_path):
    hdfs.rename(src_path, dest_path)

# Benchmarking function
def benchmark(operation, paths, nr_threads):
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=nr_threads) as executor:
        executor.map(operation, paths)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"{operation.__name__}: {len(paths)} operations in {elapsed_time:.2f} seconds.")
    return elapsed_time

# Main benchmark
def main():
    # Setup paths
    directories = [f"{BASE_DIR}/dir_{i}" for i in range(NR_FILES // NR_FILES_PER_DIR)]
    file_paths = [f"{dir}/file_{j}" for dir in directories for j in range(NR_FILES_PER_DIR)]
    rename_paths = [(file, file + "_renamed") for file in file_paths]

    # Ensure the base directory is clean
    if hdfs.path.exists(BASE_DIR):
        delete(BASE_DIR)
    mkdir(BASE_DIR)

    # Create directories
    benchmark(mkdir, directories, NR_THREADS)

    # Create files
    create_time = benchmark(create_file, file_paths, NR_THREADS)

    # Open files
    open_time = benchmark(open_file, file_paths, NR_THREADS)

    # Retrieve file status
    status_time = benchmark(file_status, file_paths, NR_THREADS)

    # Rename files
    rename_time = benchmark(lambda pair: rename(*pair), rename_paths, NR_THREADS)

    # Delete files
    delete_time = benchmark(delete, [file for file, _ in rename_paths], NR_THREADS)

    # Delete directories
    benchmark(delete, directories, NR_THREADS)

    # Summary
    print("\n--- Benchmark Summary ---")
    print(f"Create Time: {create_time:.2f}s")
    print(f"Open Time: {open_time:.2f}s")
    print(f"FileStatus Time: {status_time:.2f}s")
    print(f"Rename Time: {rename_time:.2f}s")
    print(f"Delete Time: {delete_time:.2f}s")

if __name__ == "__main__":
    main()
