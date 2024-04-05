import os
import re
import csv
import shutil

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

folder_path = os.path.join(working_dir, 'config-dev/Security inventory/macOS')
output_folder = os.path.join(working_dir, 'config/Security inventory/macOS')
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

def print_error(*args):
    error_message = " ".join(map(str, args))
    print("\033[91mError: ", error_message, "\033[0m")

def print_error_tab(*args):
    error_message = " ".join(map(str, args))
    print("\033[91m\tError: ", error_message, "\033[0m")

# Definition of the user-defined exceptions
class DisplayNameDescriptionError(Exception):
    pass

if not os.path.exists(folder_path):
    print_error("Input folder does not exist: ", folder_path)

    # Exit the script
    exit(1)

# Count subfolders
try:
    subfolders = [f.path for f in os.scandir(folder_path) if f.is_dir()]
    subfolders_count = len(subfolders)
except:
    print_error("Could not count subfolders: ", folder_path)

    # Exit the script
    exit(1)

# If there are no subfolders, exit the script
if subfolders_count == 0:
    print_error("There are no files to Process: ", folder_path)

    # Exit the script
    exit(1)

# Clean old output
try:
    if os.path.exists(output_folder):
        shutil.rmtree(output_folder)
except Exception as e:
    print_error("Could not remove old output folder:", output_folder)
    print("Exception:", e)

    # Exit the script
    exit(1)

# Normalize the paths for cross-platform compatibility
exclude_folders_cpy = [os.path.normpath('Examples')]  # Use forward slash and normpath for cross-platform paths for subfolder e.g. os.path.normpath('Examples/Test')
exclude_files_cpy = None

print("Excluding folders from cpy: ", exclude_folders_cpy)
print("Excluding files from cpy: ", exclude_files_cpy)
print("-------------------------------------")
print("Copying files...")

# Function to exclude files and folders from being processed
def exclude_function(directory, contents):
    excluded = set()
    for item in contents:
        relative_path = os.path.relpath(os.path.join(directory, item), folder_path)
        normalized_path = os.path.normpath(relative_path)  # Normalize the path for cross-platform compatibility

        if (exclude_folders_cpy and normalized_path in exclude_folders_cpy):
            excluded.add(item)
            print("\tSkipped folder: ", item)
        if (exclude_files_cpy and normalized_path in exclude_files_cpy):
            excluded.add(item)
            print("\tSkipped file: ", item)
    return excluded

# Copy the files to the output folder. Exclude specified files and folders.
try:
    shutil.copytree(folder_path, output_folder, ignore=exclude_function)
    print(f"Folder successfully copied from {folder_path} to {output_folder}")
except Exception as e:
    print(f"An error has occurred while copying files: {e}")
    exit(1)

# Create the "config-dev/generated" directory-structure if it doesn't exist
if not os.path.exists(output_csv_mapping_dir):
    try:
        os.makedirs(output_csv_mapping_dir)
    except:
        print_error("Could not create output folder: ", output_csv_mapping_dir)

        # Exit the script
        exit(1)

print("-------------------------------------")
print("Opening output csv file: ", output_csv_mapping)

# List of folders to exclude from metadata processing
exclude_folders = None
exclude_files = ["Utils.zsh"]

print("Excluding folders from metadata extraction: ", exclude_folders)
print("Excluding files from metadata extraction: ", exclude_files)

header = ["SecurityInventoryName", "SecurityInventoryDisplayName", "SecurityInventoryNameDescription"]
current_csv_data = []  # Variable for saving the CSV data

try:
    # Check whether the file exists and whether the header is present
    csv_file_exists = os.path.exists(output_csv_mapping)

    # Read the entire file, if it exists
    if csv_file_exists:
        with open(output_csv_mapping, "r", newline='', encoding='utf-8') as read_handle:
            reader = csv.reader(read_handle)
            current_csv_data = list(reader)

    # Check whether the header is present
    header_present = bool(current_csv_data) and current_csv_data[0] == header

    # Open the file in append mode
    csv_handle = open(output_csv_mapping, "a", newline='', encoding='utf-8')
    csv_writer = csv.writer(csv_handle)

    # Only write the header if the file is new or has no header
    if not csv_file_exists or not header_present:
        csv_writer.writerow(header)

except Exception as e:
    print_error(f"Could not open or read output csv file: {output_csv_mapping}, {e}")

    # Exit the script
    exit(1)

print("-------------------------------------")

def extract_values(data):
    pattern = r'(Name|DisplayName|Description)\s*=\s*["\'](.*?)["\']'
    matches = re.finditer(pattern, data, re.MULTILINE)

    extracted_values = {}
    for match in matches:
        key = match.group(1)
        value = match.group(2)
        extracted_values[key] = value

    return extracted_values

def append_mapping_info(data):

    # Check if the data['Name'] is already present in the CSV file, use current_csv_data for this
    if any(data['Name'] in sublist for sublist in current_csv_data):
        print("Test Name already present in csv: ", data['Name'])

        # Check if the DisplayName and Description are the same
        for sublist in current_csv_data:
            if sublist[0] == data['Name']:
                if sublist[1] == data['DisplayName'] and sublist[2] == data['Description']:
                    print("\tDisplayName and Description are the same, skipping...")
                    return
                else:
                    print_error_tab(f"{data['Name']}: DisplayName and Description are different, please use unique or same Description and DisplayName")
                    raise DisplayNameDescriptionError

    # Write the extracted values to a CSV file
    try:
        print("\tAppending to csv: ", data['Name'], data['DisplayName'], data['Description'])
        csv_writer.writerow([data['Name'], data['DisplayName'], data['Description']])
    except:
        print_error_tab("Could not write to csv file")

# Extracts the DisplayName and Description from a buffer
def extract_mapping_info(data):
    pattern = (
        r'(local\s+)?testName\s*=\s*"?(?!\$[0-9]+)[^"\n#]*"?\s*(#\s*[^"\n]*)?\s*'
        r'(local\s+)?testDisplayName\s*=\s*"?(?!\$[0-9]+)[^"\n#]*"?\s*(#\s*[^"\n]*)?\s*'
        r'(local\s+)?testDescription\s*=\s*"?(?!\$[0-9]+)[^"\n#]*"?(\s*#\s*[^"\n]*)?'
    )

    matches = re.finditer(pattern, data, re.MULTILINE | re.DOTALL)

    duplicate_test_names = False

    for match in matches:
        try:
            block = match.group()

            # Regex pattern to find the values of Name, DisplayName and Description
            try:
                extracted_values = extract_values(block)

                #check if all values are present
                if len(extracted_values) == 3:
                    try:
                        append_mapping_info(extracted_values)
                    except DisplayNameDescriptionError as e:
                        duplicate_test_names = True
                    except:
                        print_error_tab("Could not append mapping info")
                        raise Exception
                else:
                    print_error_tab("Not all keywords are present in the block.")
                    raise Exception
            except:
                print_error_tab("Could not extract values from block: ", block)
                raise Exception
        except:
            print_error_tab("Failed match.group")
            raise Exception

    if duplicate_test_names:
        raise Exception


# Loop through all files in the folder
for dirpath, dirnames, filenames in os.walk(output_folder):

    for filename in filenames:
        file_path = os.path.join(dirpath, filename)

        if filename in exclude_files:
            print("Skipping: ", file_path)
            counter_skipped += 1
            continue

        # Check if it's a .zsh file and not in an excluded folder
        if filename.endswith('.zsh') and (exclude_folders is None or not any(exclude_folder in file_path for exclude_folder in exclude_folders)):
            print("Processing: ", file_path )
            counter_processed += 1

            # Handle exceptions when opening the file
            try:
                # Open the file
                with open(file_path, 'r') as file:
                    # Read the contents of the file and check if the content was read successfully
                    content = file.read()

                    if not content:
                        print_error_tab("Could not read file: ", file_path)
                        continue

                    try:
                        # Extract DisplayName and Description
                        extract_mapping_info(content)
                    except:
                        print_error_tab("Failed to extract mapping info: ", file_path)
                        continue

                counter_success += 1
            except:
                print_error_tab("Could not open file: ", file_path)
        else:
            counter_skipped += 1
            print("Skipping: ", file_path)

# Print counter statistics
print("\n-------------------------------------")
print("Processed: ", counter_processed + counter_skipped, " files")
print("Skipped: ", counter_skipped, " files")
print("Success: ", counter_success, " files")
print("Failed: ", counter_processed - counter_success, " files")

# Close the CSV file
csv_handle.close()

# Check if there were any errors during the processing
if counter_processed - counter_success > 0:
    # Exit the script and stop the pipeline
    exit(1)
