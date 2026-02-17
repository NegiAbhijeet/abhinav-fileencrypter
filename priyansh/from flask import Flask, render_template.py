from flask import Flask, render_template
import pandas as pd
import matplotlib.pyplot as plt

app = Flask(__name__)

@app.route("/")
def home():
    # Dataset load
    data = pd.read_csv("crime_data.csv")
    
    # State-wise top 5
    state_crime = data.groupby("State/UT")["Cases"].sum().sort_values(ascending=False).head(5)
    
    # Save chart
    plt.figure(figsize=(6,4))
    state_crime.plot(kind="bar", color="red")
    plt.title("Top 5 States with Highest Crimes")
    plt.savefig("static/crime_chart.png")
    
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
📂 Folder structure:

pgsql
Copy code
project/
  |-- app.py
  |-- templates/
        index.html
  |-- static/
        crime_chart.png
  |-- crime_data.csv
📄 index.html

html
Copy code
<!DOCTYPE html>
<html>
<head>
    <title>Crime Data Analysis</title>
</head>
<body>
    <h1>Crime Data Analysis (India)</h1>
    <img src="/static/crime_chart.png" alt="Crime Chart">
</body>
</html>