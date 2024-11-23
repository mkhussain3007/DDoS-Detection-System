from flask import Flask, render_template, request, redirect, url_for, flash, session
import pandas as pd
import os
import subprocess
import joblib
import numpy as np
import pywt
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score
from datetime import datetime

app = Flask(__name__)

# Secret key for session management (required for flash messages)
app.secret_key = 'your_secret_key'

# Paths to store files and execute batch
network_data_file = 'network_data.csv'
prediction_file = 'predictions.csv'
batch_file_path = r"D:\Flask\CICFlowmeter\bin\CICFlowMeter.bat"  # Path to CICFlowMeter batch file

# Load the trained model (assuming you have a trained model saved as a pickle file)
scaler = joblib.load("scaler.pkl")
extra_trees_model = joblib.load("Extra Trees Classifier.pkl")

# Feature columns based on your dataset
feature_columns = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", 
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", 
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", 
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", 
    "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", 
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", 
    "Fwd PSH Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", 
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance", 
    "SYN Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "Down/Up Ratio", 
    "Average Packet Size", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", 
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", 
    "Idle Std", "Idle Max", "Idle Min", "Inbound"
    ]

# Function to capture network data and run CICFlowMeter batch file
def capture_network():
    try:
        # Run the CICFlowMeter batch file to capture network data
        result = subprocess.run(
        ["cmd", "/c", batch_file_path],
        cwd=r"D:\Flask\CICFlowmeter\bin",  # Set working directory to the batch file's location
        capture_output=True,
        text=True,
        )
        # Check result
        scaler = joblib.load("scaler.pkl")
        extra_trees_model = joblib.load("Extra Trees Classifier.pkl")
        if result.returncode == 0:
            files = [f for f in os.listdir(r'CICFlowmeter\bin\data\daily') if f.endswith('.csv')]
            if len(files) == 1:
                file_path = os.path.join(r'CICFlowmeter\bin\data\daily', files[0])
                data=pd.read_csv(file_path)
            else:
                return "No csv found"
            data.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace inf values with NaN
            data.dropna(inplace=True)
            flow_data_mapping = {
                "Flow ID": "Flow ID",
                "Src IP": "Source IP",
                "Src Port": "Source Port",
                "Dst IP": "Destination IP",
                "Dst Port": "Destination Port",
                "Protocol": "Protocol",
                "Timestamp": "Timestamp",
                "Flow Duration": "Flow Duration",
                "Tot Fwd Pkts": "Total Fwd Packets",
                "Tot Bwd Pkts": "Total Backward Packets",
                "TotLen Fwd Pkts": "Total Length of Fwd Packets",
                "TotLen Bwd Pkts": "Total Length of Bwd Packets",
                "Fwd Pkt Len Max": "Fwd Packet Length Max",
                "Fwd Pkt Len Min": "Fwd Packet Length Min",
                "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
                "Fwd Pkt Len Std": "Fwd Packet Length Std",
                "Bwd Pkt Len Max": "Bwd Packet Length Max",
                "Bwd Pkt Len Min": "Bwd Packet Length Min",
                "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
                "Bwd Pkt Len Std": "Bwd Packet Length Std",
                "Flow Byts/s": "Flow Bytes/s",
                "Flow Pkts/s": "Flow Packets/s",
                "Flow IAT Mean": "Flow IAT Mean",
                "Flow IAT Std": "Flow IAT Std",
                "Flow IAT Max": "Flow IAT Max",
                "Flow IAT Min": "Flow IAT Min",
                "Fwd IAT Tot": "Fwd IAT Total",
                "Fwd IAT Mean": "Fwd IAT Mean",
                "Fwd IAT Std": "Fwd IAT Std",
                "Fwd IAT Max": "Fwd IAT Max",
                "Fwd IAT Min": "Fwd IAT Min",
                "Bwd IAT Tot": "Bwd IAT Total",
                "Bwd IAT Mean": "Bwd IAT Mean",
                "Bwd IAT Std": "Bwd IAT Std",
                "Bwd IAT Max": "Bwd IAT Max",
                "Bwd IAT Min": "Bwd IAT Min",
                "Fwd PSH Flags": "Fwd PSH Flags",
                "Bwd PSH Flags": "Bwd PSH Flags",
                "Fwd URG Flags": "Fwd URG Flags",
                "Bwd URG Flags": "Bwd URG Flags",
                "Fwd Header Len": "Fwd Header Length",
                "Bwd Header Len": "Bwd Header Length",
                "Fwd Pkts/s": "Fwd Packets/s",
                "Bwd Pkts/s": "Bwd Packets/s",
                "Pkt Len Min": "Min Packet Length",
                "Pkt Len Max": "Max Packet Length",
                "Pkt Len Mean": "Packet Length Mean",
                "Pkt Len Std": "Packet Length Std",
                "Pkt Len Var": "Packet Length Variance",
                "FIN Flag Cnt": "FIN Flag Count",
                "SYN Flag Cnt": "SYN Flag Count",
                "RST Flag Cnt": "RST Flag Count",
                "PSH Flag Cnt": "PSH Flag Count",
                "ACK Flag Cnt": "ACK Flag Count",
                "URG Flag Cnt": "URG Flag Count",
                "CWE Flag Count": "CWE Flag Count",
                "ECE Flag Cnt": "ECE Flag Count",
                "Down/Up Ratio": "Down/Up Ratio",
                "Pkt Size Avg": "Average Packet Size",
                "Fwd Seg Size Avg": "Avg Fwd Segment Size",
                "Bwd Seg Size Avg": "Avg Bwd Segment Size",
                "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
                "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
                "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
                "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
                "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
                "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
                "Subflow Fwd Pkts": "Subflow Fwd Packets",
                "Subflow Fwd Byts": "Subflow Fwd Bytes",
                "Subflow Bwd Pkts": "Subflow Bwd Packets",
                "Subflow Bwd Byts": "Subflow Bwd Bytes",
                "Init Fwd Win Byts": "Init_Win_bytes_forward",
                "Init Bwd Win Byts": "Init_Win_bytes_backward",
                "Fwd Act Data Pkts": "act_data_pkt_fwd",
                "Fwd Seg Size Min": "min_seg_size_forward",
                "Active Mean": "Active Mean",
                "Active Std": "Active Std",
                "Active Max": "Active Max",
                "Active Min": "Active Min",
                "Idle Mean": "Idle Mean",
                "Idle Std": "Idle Std",
                "Idle Max": "Idle Max",
                "Idle Min": "Idle Min"
            }
            data.rename(columns=flow_data_mapping, inplace=True)
            # data.to_csv(r"new_csv.csv",index=False)
            # if 'Flow ID' in data.columns:
            #     data.pop('Flow ID')
            data.loc[:, 'Inbound'] = 0
            data.to_csv(r"new_csv.csv",index=False)
            # required_features = [
            # 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 
            # 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 
            # 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
            # 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 
            # 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 
            # 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 
            # 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 
            # 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'SYN Flag Count', 
            # 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 
            # 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 
            # 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 
            # 'Idle Min','Inbound'
            # ]
            
            # column_replacements = {
            # 'Fwd Header Length': 99999999,
            # 'Bwd Header Length': 999999,
            # 'Init_Win_bytes_forward': 99999,
            # 'Init_Win_bytes_backward': 99999,
            # 'min_seg_size_forward': 9999
            # }
            # for column, replacement in column_replacements.items():
            #     data[column] = data[column].apply(lambda x: replacement if x < 0 else x)
            # data = data[required_features]
            # S_data = scaler.transform(data)
            # data = pd.DataFrame(S_data, columns=required_features)
            # transformed_data = apply_wavelet_transform_2d(data)
            # predictions = extra_trees_model.predict(transformed_data)
            # labeled_predictions = label_predictions(predictions)
            # store_predictions(labeled_predictions, 'extra_trees_predictions')
            # return render_template('result.html', predictions=labeled_predictions)
            return "Network data captured successfully using CICFlowMeter!"
        else:
            return "CICFlowMeter ran but returned an error."
    except subprocess.CalledProcessError as e:
        return f"Error running CICFlowMeter: {str(e)}"

# Function to apply 2D wavelet transform to the data
def apply_wavelet_transform_2d(x):
    """Scale data, then apply 2D wavelet transform to each row in the dataset."""
    dataset = pd.concat([x, x.iloc[:, :6]], axis=1)
    scaler1=MinMaxScaler()
    test_scaled = scaler1.fit_transform(dataset)
    test_scaled_df = pd.DataFrame(test_scaled, columns=dataset.columns)
    transformed_features = []
    for _, row in test_scaled_df.iterrows():
        feature_data_reshaped = row.values.reshape(8, 8)
        coeffs2 = pywt.dwt2(feature_data_reshaped, 'haar')
        LL, (LH, HL, HH) = coeffs2
        transformed_row = np.concatenate([LL.flatten(), LH.flatten(), HL.flatten(), HH.flatten()])
        transformed_features.append(transformed_row)

    transformed_df = pd.DataFrame(np.array(transformed_features))
    return transformed_df


def label_predictions(predictions):
    """Interpret predictions as 'BENIGN' for 1 and 'ATTACK' for 0."""
    return ["BENIGN" if pred == 1 else "Attack" for pred in predictions]


def store_predictions(predictions, model_name):
    """Store the predictions in a CSV file with a timestamped filename."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    result_filename = f"{model_name}_Predictions_{timestamp}.csv"
    result_df = pd.DataFrame(predictions, columns=["Prediction"])
    result_df.to_csv(result_filename, index=False)


def evaluate_predictions_label(predictions, actual_labels):
    """Evaluate predictions against actual labels and return accuracy."""
    accuracy = accuracy_score(actual_labels, predictions)
    accuracy_percentage = accuracy * 100  # Convert to percentage
    return accuracy_percentage

# Processing functions for each option

def process_option2(data):
    """Process the data for Option 2: Best Classifier after wavelet transform."""
    data.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace inf values with NaN
    data.dropna(inplace=True)
    if 'Flow ID' in data.columns:
        data.pop('Flow ID')
    required_features = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 
    'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'SYN Flag Count', 
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 
    'Idle Min', 'Inbound'
    ]
    column_replacements = {
    'Fwd Header Length': 99999999,
    'Bwd Header Length': 999999,
    'Init_Win_bytes_forward': 99999,
    'Init_Win_bytes_backward': 99999,
    'min_seg_size_forward': 9999
    }
    
    for column, replacement in column_replacements.items():
        data[column] = data[column].apply(lambda x: replacement if x < 0 else x)
    data = data[required_features]
    S_data = scaler.transform(data)
    data = pd.DataFrame(S_data, columns=required_features)
    transformed_data = apply_wavelet_transform_2d(data)
    predictions = extra_trees_model.predict(transformed_data)
    labeled_predictions = label_predictions(predictions)
    store_predictions(labeled_predictions, 'extra_trees_predictions')
    return render_template('result.html', predictions=labeled_predictions)






def process_option5(data):
    """Process the data for Option 5: Classifier with labels after wavelet transform."""
    if 'Label' not in data.columns:
        flash("No 'Label' column found in the dataset.", "error")
        return redirect(url_for('index'))

    data.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace inf values with NaN
    data.dropna(inplace=True)  # Drop rows with NaN values

    # Separate Flow ID and Label columns\
    if 'Flow ID' in data.columns:
        data.pop('Flow ID')
    
    #flow_ids = data.pop('Flow ID')
    labels = data.pop('Label')

    required_features = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 
    'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'SYN Flag Count', 
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 
    'Idle Min', 'Inbound'
    ]

    
    # Filter the dataset to only include the required features
    
    column_replacements = {
    'Fwd Header Length': 99999999,
    'Bwd Header Length': 999999,
    'Init_Win_bytes_forward': 99999,
    'Init_Win_bytes_backward': 99999,
    'min_seg_size_forward': 9999
    }
    for column, replacement in column_replacements.items():
        data[column] = data[column].apply(lambda x: replacement if x < 0 else x)
    data = data[required_features]
    
    # Scale the filtered data
    S_data = scaler.transform(data)
    scaled_data = pd.DataFrame(S_data, columns=required_features)

    # Apply wavelet transformation
    transformed_data = apply_wavelet_transform_2d(scaled_data)

    # Make predictions
    predictions = extra_trees_model.predict(transformed_data)

    # Label predictions and store them
    labeled_predictions = label_predictions(predictions)
    labeled_predictions_df = pd.DataFrame({
        'Prediction': labeled_predictions
    })

    # Evaluate accuracy
    store_predictions(labeled_predictions_df, 'extra_trees_predictions')

    # Evaluate accuracy
    accuracy = evaluate_predictions_label(labeled_predictions, labels)
    session.clear()
    
    # Render the evaluation page with accuracy
    return render_template('evaluation.html', accuracy=accuracy)


# Route to handle file upload
@app.route('/predict_from_csv_page/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash("No file part", "error")
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash("No selected file", "error")
        return redirect(request.url)
    
    if file and file.filename.endswith('.csv'):
        # Read the CSV file
        df = pd.read_csv(file)
        option = int(request.form.get('option'))

        if option == 2:
            return process_option2(df)
        elif option == 5:
            return process_option5(df)

# Routes for various pages
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/capture_network_page')
def capture_network_page():
    message = capture_network()  # Capture the network using CICFlowMeter
    flash(message, 'success')  # Flash message for success
    return render_template('capture_network.html', message=message)

@app.route('/predict_from_csv_page', methods=['GET', 'POST'])
def predict_from_csv_page():
    return render_template('predict_from_csv.html')

if __name__ == '__main__':
    app.run(debug=True)
