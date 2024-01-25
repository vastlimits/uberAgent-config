import os
import re
import csv

try:
    # Path to the folder to search
    working_dir = os.getcwd()
except:
    print("Error: Could not get current working directory")

    # Exit the script
    exit(1)

counter_skipped = 0
counter_success = 0
counter_processed = 0

folder_path = os.path.join(working_dir, 'config-dev/Security inventory/Windows')
output_folder = os.path.join(working_dir, 'config/Security inventory/Windows')
output_csv_mapping_dir = os.path.join(working_dir, 'config-dev/generated')
output_csv_mapping = os.path.join(output_csv_mapping_dir, 'security_inventory_checknames.csv')

print("-------------------------------------")
print("Current working dir: ", working_dir)
print("Using input: ", folder_path)
print("Using output: ", output_folder)
print("Using output mapping dir: ", output_csv_mapping_dir)
print("Using output mapping csv: ", output_csv_mapping)
print("-------------------------------------")
print("Cleaning old output...")

if not os.path.exists(folder_path):
    print("Error: Input folder does not exist: ", folder_path)

    # Exit the script
    exit(1)

# Count subfolders
subfolders = [f.path for f in os.scandir(folder_path) if f.is_dir()]
subfolders_count = len(subfolders)

# If there are no subfolders, exit the script
if subfolders_count == 0:
    print("Error: There are no files to Process: ", folder_path)

    # Exit the script
    exit(1)

# Create the "transpiled" directory-structure if it doesn't exist
if not os.path.exists(output_folder):
    try:
        os.makedirs(output_folder)
    except:
        print("Error: Could not create output folder: ", output_folder)

        # Exit the script
        exit(1)

# Create the "config-dev/generated" directory-structure if it doesn't exist
if not os.path.exists(output_csv_mapping_dir):
    try:
        os.makedirs(output_csv_mapping_dir)
    except:
        print("Error: Could not create output folder: ", output_csv_mapping_dir)

        # Exit the script
        exit(1)

# Clean old output
for dirpath, dirnames, filenames in os.walk(output_folder):
    for filename in filenames:
        file_path = os.path.join(dirpath, filename)
        # Check if file_path  contains a file
        if os.path.isfile(file_path):
            try:
                # Delete file
                os.remove(file_path)
            except:
                print("Error: Could not delete file: ", file_path)

                # Exit the script
                exit(1)

# clean old security_inventory_checknames.csv using path output_csv_mapping
if os.path.isfile(output_csv_mapping):
    try:
        # Delete old mapping file
        os.remove(output_csv_mapping)
    except:
        print("Error: Could not delete file: ", output_csv_mapping)

        # Exit the script
        exit(1)

print("-------------------------------------")

# List of folders to exclude
exclude_folders = None #['']

print("Excluding folders: ", exclude_folders)
print("-------------------------------------")
print("Opening output csv file: ", output_csv_mapping)

try:
    csv_handle = open(output_csv_mapping, "w", newline='', encoding='utf-8')
    csv_writer = csv.writer(csv_handle)
    csv_writer.writerow(["SecurityInventoryName", "SecurityInventoryDisplayName", "SecurityInventoryNameDescription"])
except:
    print("Error: Could not open output csv file: ", output_csv_mapping)

    # Exit the script
    exit(1)
print("-------------------------------------")

####### ENV_WORKFLOW_FILE #######
env_file = os.getenv('GITHUB_ENV') # Get the path of the runner file

def update_key(key, value):
    data = {}
    try:
        with open(env_file, 'r') as file:
            for line in file:
                if line.strip():
                    k, v = line.strip().split('=')
                    data[k] = v
    except FileNotFoundError:
        pass

    data[key] = value

    with open(env_file, 'w') as file:
        for k, v in data.items():
            file.write(f'{k}={v}\n')


def read_key(key):
    try:
        with open(env_file, 'r') as file:
            for line in file:
                if line.strip():
                    k, v = line.strip().split('=')
                    if k == key:
                        return v
    except FileNotFoundError:
        print(f"Error: The file '{env_file}' was not found.")

    print(f"Error: The key '{key}' was not found.")
    return None

def extract_values(data):
    try:
        pattern = r'(Name|DisplayName|Description)\s*=\s*["\'](.*?)["\']'
        matches = re.finditer(pattern, data, re.MULTILINE)

        extracted_values = {}
        for match in matches:
            key = match.group(1)
            value = match.group(2)
            extracted_values[key] = value
    except:
        print("Error: Could not find Name, DisplayName and Description for pattern")
        raise Exception

    return extracted_values

def append_mapping_info(data):
    # Write the extracted values to a CSV file
    try:
        print("\tAppending to csv: ", data['Name'], data['DisplayName'], data['Description'])
        csv_writer.writerow([data['Name'], data['DisplayName'], data['Description']])
    except:
        print("\tError: Could not write to csv file")

# Extracts the DisplayName and Description from a buffer
def extract_mapping_info(data):

    keywords = ["Name", "DisplayName", "Description", "Score", "ResultData", "RiskScore", "ErrorCode", "ErrorMessage"]

    try:
        pattern = r'\[PSCustomObject\]@\{[^{}]*(((?<=[^{}])\{[^{}]*(((?<=[^{}])\{[^{}]*(((?<=[^{}])\{[^{}]*\})[^{}]*)*\})[^{}]*)*\})[^{}]*)*\}'
        matches = re.finditer(pattern, data, re.MULTILINE | re.DOTALL)
    except:
        print("\tError: Could not find PSCustomObject for pattern")
        raise Exception

    for match in matches:
        try:
            block = match.group()

            all_keywords_present = True
            for keyword in keywords:
                if keyword not in block:
                    all_keywords_present = False
                    break
            if all_keywords_present:
                # Regex pattern to find the values of Name, DisplayName and Description
                try:
                    extracted_values = extract_values(block)

                    #check if all values are present
                    if len(extracted_values) == 3:
                        append_mapping_info(extracted_values)
                    else:
                        print("\tNot all keywords are present in the block.")
                        raise Exception
                except:
                    print("\tError: Could not extract values from block: ", block)
                    raise Exception
        except:
            print("\tError: Failed match.group")
            raise Exception


# Loop through all files in the folder
for dirpath, dirnames, filenames in os.walk(folder_path):

    for filename in filenames:
        file_path = os.path.join(dirpath, filename)

        # Check if it's a .ps1 file and not in an excluded folder
        if filename.endswith('.ps1') and (exclude_folders is None or not any(exclude_folder in file_path for exclude_folder in exclude_folders)):
            print("Processing: ", file_path )
            counter_processed += 1

            # Handle exceptions when opening the file
            try:
                # Open the file
                with open(file_path, 'r') as file:
                    # Read the contents of the file and check if the content was read successfully
                    content = file.read()

                    if not content:
                        print("\tError: Could not read file: ", file_path)
                        continue

                    try:
                        # Extract DisplayName and Description
                        extract_mapping_info(content)
                    except:
                        print("\tError: Failed to extract mapping info: ", file_path)
                        continue

                    # Extract subfolder name
                    subfolder = os.path.relpath(os.path.dirname(file_path), folder_path)

                    # Write the transpiled contents to a new file in the "transpiled" directory
                    transpiled_path = os.path.join(output_folder, subfolder, filename)
                    transpiled_path_dir = os.path.join(output_folder, subfolder)

                    # Create subfolders if missing
                    if not os.path.exists(transpiled_path_dir):
                        try:
                            os.makedirs(transpiled_path_dir)
                        except:
                            print("\tError: Could not create output folder: ", transpiled_path_dir)
                            continue

                    print("\tWriting file: ", transpiled_path)

                    # Handle exceptions when opening the file
                    try:
                        with open(transpiled_path, 'w') as transpiled_file:
                            #check if the content was successfully written
                            num_written = transpiled_file.write(content)
                            if num_written == 0:
                                print("\tError: Could not write to file: ", transpiled_path)
                            elif num_written != len(content):
                                print("\tError: Could not write all content to file: ", transpiled_path)
                            else:
                                print("\tSuccess: ", num_written, " bytes written")
                    except:
                        print("\tError: Could not open transpiled file: ", transpiled_path)
            except:
                print("\tError: Could not open file: ", file_path)

            counter_success += 1
        else:
            counter_skipped += 1
            print("Skipping: ", file_path)

# Print counter statistics
print("\n-------------------------------------")
print("Processed: ", counter_processed + counter_skipped, " files")
print("Skipped: ", counter_skipped, " files")
print("Success: ", counter_success, " files")
print("Failed: ", counter_processed - counter_success, " files")

update_key("TRANSPILER_SUCCSESS", str(counter_success))
update_key("TRANSPILER_PROCESSED", str(counter_processed))
update_key("TRANSPILER_FAILED", str(counter_processed - counter_success))

# Close the CSV file
csv_handle.close()