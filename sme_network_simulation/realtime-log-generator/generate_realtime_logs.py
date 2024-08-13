import json
import random
import time
import pandas as pd
from datetime import datetime

# Generate real-time log data
while True:
    log_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "activity": random.choice(["login", "logout", "file_create", "file_delete", "send_email", "receive_email"])
    }

    log_df = pd.DataFrame([log_data])
    log_df.to_csv('/mnt/data/realtime_logs.csv', mode='a', header=False, index=False)
    time.sleep(1)
