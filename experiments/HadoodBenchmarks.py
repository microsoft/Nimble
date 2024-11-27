import time
from concurrent.futures import ThreadPoolExecutor
from nimble import NimbleClient

client = NimbleClient()

# Utility functions for operations
def create_file(file_path):
    with client.open(file_path, "w") as f:
        f.write("test")  # Example content.

def mkdir(dir_path):
    client.mkdir(dir_path)

def open_file(file_path):
    with client.open(file_path, "r") as f:
        f.read()  # Simulates opening and reading.

def delete_file_or_dir(file_path):
    client.delete(file_path)

def file_status(file_path):
    return client.get_file_status(file_path)

def rename_file(src_path, dest_path):
    client.rename(src_path, dest_path)

# Benchmark framework
def benchmark(operation, paths, nrThreads):
    start = time.time()
    with ThreadPoolExecutor(max_workers=nrThreads) as executor:
        executor.map(operation, paths)
    end = time.time()
    print(f"{operation.__name__}: Processed {len(paths)} items in {end - start:.2f} seconds.")
    return end - start

# Main benchmark for all operations
def main_benchmark(nrFiles=500000, nrThreads=64, nrFilesPerDir=4):
    directories = [f"/dir_{i}" for i in range(nrFiles // nrFilesPerDir)]
    file_paths = [f"{dir}/file_{j}" for dir in directories for j in range(nrFilesPerDir)]
    rename_paths = [(file, file + "_renamed") for file in file_paths]

    # Ensure directories exist
    benchmark(mkdir, directories, nrThreads)

    # 1. Create files
    create_time = benchmark(create_file, file_paths, nrThreads)

    # 2. Open files
    open_time = benchmark(open_file, file_paths, nrThreads)

    # 3. Retrieve fileStatus
    status_time = benchmark(file_status, file_paths, nrThreads)

    # 4. Rename files
    rename_time = benchmark(lambda pair: rename_file(*pair), rename_paths, nrThreads)

    # 5. Delete files
    delete_time = benchmark(delete_file_or_dir, [file for file, _ in rename_paths], nrThreads)

    # Delete directories
    benchmark(delete_file_or_dir, directories, nrThreads)

    # Summary
    print("\n--- Benchmark Summary ---")
    print(f"Create Time: {create_time:.2f}s")
    print(f"Open Time: {open_time:.2f}s")
    print(f"FileStatus Time: {status_time:.2f}s")
    print(f"Rename Time: {rename_time:.2f}s")
    print(f"Delete Time: {delete_time:.2f}s")

# Run benchmark
main_benchmark(nrFiles=500000, nrThreads=64, nrFilesPerDir=4)
