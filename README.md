# Network Intrusion Detection System (NIDS) using Machine Learning

## Overview

This project implements a **Network Intrusion Detection System (NIDS)** leveraging machine learning techniques on network traffic data. It uses the popular **NSL-KDD** dataset to train a Random Forest classifier that can detect attacks based on network traffic features.  
Additionally, it can analyze real network captures (.pcapng files) to detect potential intrusions in live traffic.

---

## Features

- Train a Random Forest model on NSL-KDD dataset  
- Predict intrusion on new network flow data via CLI  
- Extract features from .pcapng files (Wireshark captures) and detect attacks  
- Scalable and extensible with saved models and preprocessors  
- Useful for cybersecurity and machine learning learning paths  

---

## Dataset

This project uses the **NSL-KDD** dataset for model training and evaluation.

> **Note:** The dataset files (`KDDTrain+.txt`, `KDDTest+.txt`) are **not included** due to size and licensing constraints.  
> Please download the dataset from [Kaggle NSL-KDD Dataset](https://www.kaggle.com/datasets/hassan06/nslkdd)  
> and place the downloaded files inside the `data/` directory.

---

## Network Traffic Capture (PCAP)

To test the model on real network traffic:

1. Use [Wireshark](https://www.wireshark.org/) to capture network traffic.  
2. Save the capture file as `capture.pcapng` in the root project directory.  
3. **Important:** Avoid uploading or sharing `.pcap` or `.pcapng` files publicly as they may contain sensitive information.

---

## Installation

1. Clone the repository:
    
    bash
        git clone https://github.com/nihal-shetty/nids-ml.git
        cd nids-ml

2. Install dependencies:
    
    bash
        pip install -r requirements.txt

3. Download and place dataset files as described above.

---

## Usage

### 1. Train Model

Run the training script to train the model and save the preprocessing objects:

    bash
        python src/train_model.py

### 2. Predict via CLI

Use the CLI interface to predict intrusion from manual input of 41 features:

    bash
        python cli.py

Enter 41 comma-separated feature values as prompted (categorical fields like `protocol_type`, `service`, and `flag` should be the original string labels).

### 3. Predict from PCAP

Use a network capture file to extract features and detect attacks:

    bash
        python src/predict_from_pcap.py

Make sure `capture.pcapng` is present in the project root.

---

## Project Structure

    nids-ml/
    │
    ├── data/
    │   ├── KDDTrain+.txt
    │   ├── KDDTest+.txt
    │
    ├── models/
    │   ├── nids_model.pkl
    │   ├── encoder_protocol.pkl
    │   ├── encoder_service.pkl
    │   ├── encoder_flag.pkl
    │   ├── scaler.pkl
    │
    ├── src/
    │   ├── preprocess.py
    │   ├── train_model.py
    │   ├── predict_from_pcap.py
    │
    ├── cli.py
    ├── capture.pcapng        # Optional: your Wireshark capture file
    ├── README.md
    ├── requirements.txt

---

## License

This project is for educational purposes.  
Dataset license: NSL-KDD Dataset License

---

## Contact

Created by Nihal Shetty  
Email: nihal.shetty@example.com  
GitHub: [nihal-shetty](https://github.com/nihal-shetty)

Feel free to reach out with questions or feedback!  
Happy hacking 🔐🚀
