import tempfile
import os

# For TemporaryDirectory
temp_dir_obj = tempfile.TemporaryDirectory()
temp_dir = temp_dir_obj.name
print(f"Temporary directory created: {temp_dir}")
# Create files within temp_dir
with open(os.path.join(temp_dir, "my_temp_file.txt"), "w") as f:
    f.write("Some data")

input("Press Enter to clean up the temporary directory...")
#temp_dir_obj.cleanup()
print("Temporary directory cleaned up.")

# For NamedTemporaryFile
temp_file_obj = tempfile.NamedTemporaryFile(delete=False) # Important: delete=False
temp_file_name = temp_file_obj.name
temp_file_obj.write(b"Some temporary content")
temp_file_obj.close()
print(f"Temporary file created: {temp_file_name}")

input("Press Enter to delete the temporary file...")
#os.remove(temp_file_name)
print("Temporary file deleted.")
