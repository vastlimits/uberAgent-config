import os
import re
import csv

try:
    # Path to the folder to search
    working_dir = os.getcwd()
except:
    print("Error: Could not get current working directory")

    # Exit the script
    exit()

counter_skipped = 0
counter_success = 0
counter_processed = 0

folder_path = os.path.join(working_dir, 'config-dev/Security inventory/Windows')
include_folder = os.path.join(working_dir, 'config-dev/Security inventory/Windows/Shared')
output_folder = os.path.join(working_dir, 'config/Security inventory/Windows')
output_csv_mapping = os.path.join(working_dir, 'config/security_inventory_checknames.csv')

print("-------------------------------------")
print("Current working dir: ", working_dir)
print("Using input: ", folder_path)
print("Using include: ", include_folder)
print("Using output: ", output_folder)
print("Using output csv: ", output_csv_mapping)
print("-------------------------------------")
print("Cleaning old output...")

# Count subfolders if the input folder
subfolders = [f.path for f in os.scandir(folder_path) if f.is_dir()]
subfolders_count = len(subfolders)

# If there are no subfolders, exit the script
if subfolders_count == 0:
    print("Error: There are no files to Process: ", folder_path)

    # Exit the script
    exit()

# Create the "transpiled" directory-structure if it doesn't exist
if not os.path.exists(output_folder):
    try:
        os.makedirs(output_folder)
    except:
        print("Error: Could not create output folder: ", output_folder)

        # Exit the script
        exit()
    
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
                exit()

# clean old security_inventory_checknames.csv using path output_csv_mapping
if os.path.isfile(output_csv_mapping):
    try:
        # Delete old mapping file
        os.remove(output_csv_mapping)
    except:
        print("Error: Could not delete file: ", output_csv_mapping)

        # Exit the script
        exit()

print("-------------------------------------")

# List of folders to exclude
exclude_folders = ['Shared']
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
    exit()
print("-------------------------------------")

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
        if filename.endswith('.ps1') and not any(exclude_folder in file_path for exclude_folder in exclude_folders):
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
        
                    # Search for includes
                    includes = re.findall(r'(?<=Shared\\)[^\\]+\.ps1', content, flags=re.IGNORECASE)
                    
                    print("\tFound: ", len(includes), " include(s)")
        
                    # Loop through all found includes
                    for include in includes:
                        # Replace the include with the contents of the corresponding file
                        include_path = os.path.join(include_folder, include)

                        # Handle exceptions when opening the file
                        try:
                            with open(include_path, 'r') as include_file:
                                include_content = include_file.read()

                                # Read the contents of the file and check if the content was read successfully
                                if not include_content:
                                    print("\tError: Could not read include file: ", include_path)
                                    continue

                                includes_ex = re.findall(r'.*(?<=Shared\\)' + re.escape(include) + r'.*', content, flags=re.IGNORECASE)
                                
                                if len(includes_ex) > 0:
                                    content = content.replace(includes_ex[0], include_content)
                                    
                                content = re.sub(r'.*#Requires.*(\r?\n)?', '', content, flags=re.IGNORECASE)
                        except:
                            print("\tError: Could not open include file: ", include_path)
        
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
print("Processed: ", counter_processed, " files")
print("Skipped: ", counter_skipped, " files")
print("Success: ", counter_success, " files")
print("Failed: ", counter_processed - counter_success, " files")

# Close the CSV file
csv_handle.close()