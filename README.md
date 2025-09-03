# CAPSTONE 2026: Neural Network- Based Anomaly Detection and Adaptive QoS Mitigation with Honeypot Defense in SDN

## Overview
This project implements a machine learning approach for detecting anomalies in encrypted network traffic within a Software-Defined Networking (SDN) environment. The system utilizes Mininet for network simulation, Ryu as an SDN controller, and a trained ML model for anomaly detection.

## Prerequisites
### System Requirements
- Ubuntu 20.04 or later
- Python 3.9
- Mininet
- Open vSwitch

### Installation Steps
1. Update system packages:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
2. Install dependencies:
   ```bash
   sudo apt install mininet python3-pip openvswitch-switch tcpdump
   sudo add-apt-repository ppa:deadsnakes/ppa -y
   sudo apt update
   sudo apt install python3.9 python3.9-venv python3.9-dev -y
   ```
3. Create and activate a virtual environment:
   ```bash
   python3.9 -m venv myenv39
   source myenv39/bin/activate
   ```
4. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Dataset Preparation
1. Download the CIC-IDS2017 dataset. (It is also available https://drive.google.com/drive/folders/1kSNKSGeiKaRAoVMY8cIcMQ_FM1rMUdEY)
2. Store the CSV files inside `ML_Model_Latest/data/` (GitHub does not support large file uploads).
3. Preprocess the dataset:
   ```bash
   cd data_processing
   python preprocess_cicids.py
   ```

## Collecting Live Network Traffic
To collect real-time network traffic for training:
```bash
sudo env "PATH=$PATH" python3 mininet-data-collector.py
```
This will generate a CSV file inside the `mininet` folder, which should be moved to `ML_Model_Latest/` for training.

## Training the Model
```bash
cd ml_model
python train_model.py
```

## Running the SDN Controller
```bash
cd controller
ryu-manager ryu_controller.py
```

## Running Mininet Topology
```bash
cd mininet
sudo python3 test_topology.py
```

## Execution Workflow
### Terminal 1 (Controller):
```bash
source ~/myenv39new/bin/activate
cd Capstone_Phase3/controller/
ryu-manager ryu_controller.py
```
### Terminal 2 (Mininet Topology Simulation):
```bash
cd Capstone_Phase3/mininet/
sudo python3 test_topology.py
```
### Terminal 3 (Start Analytics Dshboard):
```bash
cd Capstone_Phase3/
./run_dashboard.sh #OPen dashboard in http://127.0.0.1:8501/
```
## Cleanup
After execution, clean up Mininet:
```bash
sudo mn -c
```

## Contributors
- **Sandeep Elayath**
- **Safdar Ahmad**
- **Vidhan Viswas**
- **Basavraj Naikal**

## License
This project is open-source and available under the MIT License.

