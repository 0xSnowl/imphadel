import pickle
import argparse
import pandas as pd
import pefile
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.exceptions import ConvergenceWarning
from colorify import *
import warnings

warnings.simplefilter("ignore", category=UserWarning)

# Load the saved model and the column names
with open("decision_tree_model_and_columns.pkl", "rb") as file:
    loaded_model, trained_columns = pickle.load(file)

def extract_meta(exe_name):

    print(colorify("Beginning metadata extraction", C.orange))
    # Define the metadata fields to extract
    metadata = {"Name": [],
                "Timestamp": [],
                "Number of sections": [],
                "Section alignment": [],
                "File alignment": [],
                "Size of image": [],
                "Size of headers": [],
                "Subsystem": [],
                "DLL characteristics": [],
                "Imported DLLs": [],
                "Imported functions": [],
                "Exported symbols": []}



    # Open the PE file
    pe = pefile.PE(exe_name)

    # Extract the metadata fields
    metadata["Name"].append(pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "Unknown"))
    metadata["Timestamp"].append(pe.FILE_HEADER.TimeDateStamp)
    metadata["Number of sections"].append(pe.FILE_HEADER.NumberOfSections)
    metadata["Section alignment"].append(pe.OPTIONAL_HEADER.SectionAlignment)
    metadata["File alignment"].append(pe.OPTIONAL_HEADER.FileAlignment)
    metadata["Size of image"].append(pe.OPTIONAL_HEADER.SizeOfImage)
    metadata["Size of headers"].append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    metadata["Subsystem"].append(pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown"))
    metadata["DLL characteristics"].append(",".join([pefile.DLL_CHARACTERISTICS[x] for x in [pe.OPTIONAL_HEADER.DllCharacteristics] if x in pefile.DLL_CHARACTERISTICS]))
    metadata["Imported DLLs"].append(",".join([entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else "")
    metadata["Imported functions"].append(",".join([f.name.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT for f in entry.imports if f.name is not None]) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else "")
    metadata["Exported symbols"].append(",".join([exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name is not None]) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else "")
    
    # Close the PE file
    pe.close()

    print(colorify("Extraction Completed", C.orange))
    return pd.DataFrame(metadata)

def encode_meta(meta_df):
    print(colorify("Beginning encoding process", C.orange))

    # Splitting the strings into lists
    meta_df['Imported DLLs'] = meta_df['Imported DLLs'].apply(lambda x: x.split(',') if x else [])
    meta_df['Imported functions'] = meta_df['Imported functions'].apply(lambda x: x.split(',') if x else [])
    meta_df['Exported symbols'] = meta_df['Exported symbols'].apply(lambda x: x.split(',') if x else [])

    # Encoding the columns
    mlb = MultiLabelBinarizer()

    encoded_imported_dlls = pd.DataFrame(mlb.fit_transform(meta_df['Imported DLLs']), columns=mlb.classes_, index=meta_df.index)
    encoded_imported_functions = pd.DataFrame(mlb.fit_transform(meta_df['Imported functions']), columns=mlb.classes_, index=meta_df.index)
    encoded_exported_symbols = pd.DataFrame(mlb.fit_transform(meta_df['Exported symbols']), columns=mlb.classes_, index=meta_df.index)

    # Concatenating the encoded columns with the original dataframe
    meta_df_encoded = pd.concat([meta_df, encoded_imported_dlls, encoded_imported_functions, encoded_exported_symbols], axis=1)

    # Dropping the original columns
    meta_df_encoded = meta_df_encoded.drop(['Imported DLLs', 'Imported functions', 'Exported symbols'], axis=1)
    meta_df_encoded.head()

    meta_df_encoded = pd.get_dummies(meta_df_encoded, columns=['Name', 'Subsystem', 'DLL characteristics'])
    
    print(colorify("Encoding Completed", C.orange))
    return meta_df_encoded

def extract_meta_and_encode(exe_name):
    # Assuming extract_meta function returns the encoded DataFrame
    meta_df = extract_meta(exe_name)
    encoded_df = encode_meta(meta_df)

    return encoded_df

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Malware Classifier")
parser.add_argument("exe_name", help="Name of the executable file")
args = parser.parse_args()

# Get the encoded DataFrame for the given executable file
encoded_df = extract_meta_and_encode(args.exe_name)

# Align the encoded_df DataFrame to have the same columns as the saved column names
encoded_df = encoded_df.reindex(columns=trained_columns, fill_value=0)

# Make a prediction using the loaded model
prediction = loaded_model.predict(encoded_df)

# Print the classification result
if prediction[0] == 0:
    print(colorify(f"{args.exe_name.split('/')[-1]} is NOT malware.", C.green))
else:
    print(colorify(f"{args.exe_name.split('/')[-1]} is MALWARE.", C.red))
