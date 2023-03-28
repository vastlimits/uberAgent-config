import os
import re
import json

def get_log_level_priority(level):
    try:
        priorities = {'none': 0, 'note': 1, 'warning': 2, 'error': 3}
        return priorities.get(level, 0)
    except:
        return 0

def should_print_log(level, log_level_priority):
    return get_log_level_priority(level) >= log_level_priority

def should_fail(level, fail_level_priority):
    return get_log_level_priority(level) >= fail_level_priority

try:
    # Path to the folder to search
    working_dir = os.getcwd()
except:
    print("Error: Could not get current working directory")

    # Exit the script
    exit(1)

try:
    # Get the log level from the environment variable
    # Log level can be one of the following: error, warning, note, none
    # Fail level can be one of the following: error, warning, note, none
    # If the log level is set to none, no log will be generated
    # The log level will always include the upper levels (e.g. if the log level is set to warning, it will also log errors and warnings)
    # If the fail level is set to none, the script will not fail
    # If the fail level is set to note it will fail if there is an error, warning or a note

    log_level = os.getenv('log_level').toLower() if os.getenv('log_level') else 'note'
    fail_level = os.getenv('fail_level').toLower() if os.getenv('fail_level') else 'note'
except:
    print("Error: Could not get environment variables")

    # Exit the script
    exit(1)


log_level_priority = get_log_level_priority(log_level)
fail_level_priority = get_log_level_priority(fail_level)

return_status = 0
log_file_path = os.path.join(working_dir, 'config-dev/generated/psscriptanalyzer_log.sarif')

print("-------------------------------------")
print("Current working dir: ", working_dir)
print("Using Logfile: ", log_file_path)
print("-------------------------------------")

if not os.path.isfile(log_file_path):
    print("Error: Could not find sarif file")

    # Exit the script
    os._exit(1)

try:
    with open(log_file_path, 'r') as file:
        sarif_data = json.load(file)

    try:
        errors = []
        warnings = []
        notes = []

        for run in sarif_data['runs']:
            for result in run['results']:
                level = result['level'] if 'level' in result else ''
                message = result['message']['text'] if 'level' in result and 'text' in result['message'] else ''

                try:
                    location = result['locations'][0]['physicalLocation']['artifactLocation']['uri']

                    regex = regex = r"file:\/\/\/home\/runner\/work\/uberAgent-config\/uberAgent-config\/config\/[^\/]*\/(.*)"
                    location = re.sub(regex, r"\1", location)
                except:
                    location = 'Error while extracting location'

                try:
                    line = result['locations'][0]['physicalLocation']['region']['startLine']
                except:
                    line = 'Error while extracting line'

                if level == 'error':
                    errors.append(f"\033[91mERROR\033[0m in {location} line {line}: {message}")
                elif level == 'warning':
                    warnings.append(f"\033[93mWARNING\033[0m in {location} line {line}: {message}")
                elif level == 'note':
                    notes.append(f"\033[94mNOTE\033[0m in {location} line {line}: {message}")

        if should_print_log('error', log_level_priority):
            print("-------------------------------------")
            print("Errors:")
            for error in errors:
                print(error)
        
        if should_print_log('warning', log_level_priority):
            print("-------------------------------------")
            print("Warnings:")
            for warning in warnings:
                print(warning)
        
        if should_print_log('note', log_level_priority):
            print("-------------------------------------")
            print("Notes:")
            for note in notes:
                print(note)

        if fail_level_priority > 0:
            if should_fail('error', fail_level_priority) and len(errors) > 0:
                return_status = 1
            elif should_fail('warning', fail_level_priority) and (len(errors) > 0 or len(warnings) > 0):
                return_status = 1
            elif should_fail('note', fail_level_priority) and (len(errors) > 0 or len(warnings) > 0 or len(notes) > 0):
                return_status = 1
            else:
                return_status = 0
        else:
                return_status = 0

        print("-------------------------------------")
        print(f"Found {len(errors)} errors, {len(warnings)} warnings and {len(notes)} notes")
        print("Exit code: " + str(return_status))
        print("-------------------------------------")
    
        os._exit(return_status)
    except:
        print("Error: Could not parse sarif file")

        # Exit the script
        os._exit(1)
except:
    print("Error: Could not open sarif file")

    # Exit the script
    os._exit(1)