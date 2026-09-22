# CipherSense — Adaptive Block Cipher Selector

An interactive cryptographic decision-support system that helps users select an appropriate **block cipher** based on their security, performance, hardware, and application requirements.

CipherSense transforms technical cryptographic properties into an accessible questionnaire for non-expert users. Rather than relying on a fixed decision tree, the system dynamically evaluates the remaining cipher candidates, selects informative questions, applies hard requirements, and ranks the best-matching algorithms.

---

<h2 align="center">🎥 Application Demo</h2>

<p align="center">
  <strong>See CipherSense explore block ciphers, adapt its questionnaire, and generate personalized cryptographic recommendations.</strong>
</p>

<h3 align="center">
  <a href="https://drive.google.com/file/d/10oVz2BhNb2mhnv0tQbY9TtUNqfjG8smA/view?usp=sharing">
    ▶️ WATCH THE DEMO
  </a>
</h3>

---

## 🎯 What Problem Does CipherSense Solve?

Choosing a block cipher involves more than simply selecting the algorithm with the largest key.

Different environments have different requirements:

- How strong does the security need to be?
- Will the cipher run on a low-power or constrained device?
- Is high throughput important?
- Is hardware acceleration available?
- Does the algorithm need to be standardized?
- Will it be used for storage, TLS/VPN traffic, or streaming?
- Is compatibility with legacy systems important?

CipherSense converts these technical tradeoffs into understandable questions and uses the answers to progressively narrow and rank suitable cryptographic algorithms.

---

## Features

### 🧠 Adaptive Question Selection

The questionnaire is **not limited to a static sequence of questions**.

For each step, CipherSense analyzes the remaining cipher candidates and determines which unanswered question provides the most useful split between them.

This allows the system to reduce ambiguity efficiently instead of asking every user the same questions in the same order.

### 🔍 Hard Constraint Filtering

Requirements that cannot be compromised are treated as hard constraints.

For example, CipherSense can eliminate algorithms that:

- Do not satisfy the required security level
- Are unsuitable for constrained or low-power devices
- Do not meet minimum key-size requirements
- Use an unsuitable block size for the requested data volume
- Fail required standardization criteria

Only feasible candidates continue through the selection process.

### 📊 Preference-Based Ranking

Not every requirement needs to eliminate an algorithm.

CipherSense also assigns preference scores based on how closely each remaining cipher matches the user's environment.

Ranking considers properties such as:

- Security strength
- Key size
- Block size
- Processing speed
- Low-power suitability
- Hardware acceleration
- Standardization
- TLS/VPN suitability
- Storage suitability
- High-throughput streaming suitability
- Intended/common use

The highest-ranking candidates are presented as recommendations.

### 🔐 Cipher Explorer

Users can browse the cipher database before starting the questionnaire.

Each cipher includes information such as:

- Structure
- Security level
- Key size
- Block size
- Processing characteristics
- Common use cases
- Known vulnerabilities
- Relevant references

### 🌐 Interactive Web Interface

CipherSense includes a Flask-powered web application with:

- Interactive cipher exploration
- Animated cyber-themed interface
- Adaptive questionnaire
- Live remaining-candidate counts
- Ranked recommendation results
- Detailed cipher properties
- Additional matching candidates

A command-line implementation of the selection algorithm is also included.

---

## ⚙️ How the Selection Engine Works

```text
                 User Requirements
                        │
                        ▼
              ┌───────────────────┐
              │ Remaining Ciphers │
              └─────────┬─────────┘
                        │
                        ▼
             Evaluate Unasked Questions
                        │
                        ▼
              Find Informative Split
                        │
                        ▼
                  Ask Question
                        │
                        ▼
                Apply User Answer
                   /          \
                  /            \
                 ▼              ▼
        Hard Constraints    Soft Preferences
                 │              │
                 └──────┬───────┘
                        ▼
                 Reduce Candidates
                        │
                  More Questions?
                    /       \
                  Yes        No
                   │          │
                   └───┐      ▼
                       │   Rank Remaining
                       │      Ciphers
                       │        │
                       └────────┤
                                ▼
                     Recommended Ciphers
```

### 1. Candidate Filtering

The system begins with the complete cipher dataset.

As the user answers questions, hard requirements remove incompatible algorithms from consideration.

### 2. Adaptive Questioning

For each unanswered question, the system examines how that question would divide the remaining candidates into different answer categories.

It then prioritizes questions that effectively separate the candidate pool, allowing useful information to be collected earlier.

### 3. Preference Scoring

Remaining algorithms receive scores based on how closely their characteristics match the user's preferences.

### 4. Final Ranking

Once sufficient information has been collected, the remaining candidates are ranked and the strongest matches are presented along with their technical characteristics.

---

## 🛠️ Tech Stack

### Backend

`Python` · `Flask`

### Frontend

`HTML5` · `CSS3` · `JavaScript` · `Jinja2`

### Cryptographic Decision Engine

`Adaptive Filtering` · `Constraint Evaluation` · `Preference Scoring` · `Candidate Ranking`

### Data

`CSV` · `Python csv module`

---

## 📂 Project Structure

```text
CipherSense-Adaptive-Cipher-Selector/
│
├── static/
│   ├── style.css
│   └── cyber.js
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── question.html
│   └── results.html
│
├── adaptive.py
├── app.py
├── Table.csv
├── requirements.txt
├── .gitignore
└── README.md
```

### Core Files

**`adaptive.py`**  
Implements the cipher-selection engine, including question generation, candidate filtering, adaptive question selection, preference scoring, and final ranking.

**`app.py`**  
Flask application connecting the selection engine to the web interface and managing questionnaire sessions.

**`Table.csv`**  
Cryptographic knowledge base containing the technical and practical properties used to evaluate each block cipher.

**`templates/`**  
Jinja2 templates for the cipher explorer, questionnaire, and recommendation results.

**`static/`**  
CSS and JavaScript responsible for the application's styling, animations, cipher modals, and interactive behavior.

---

# 🚀 Running CipherSense Locally

## Prerequisites

Before running the application, make sure you have:

- **Python 3.9 or newer**
- **pip**
- **Git**

You can verify Python is installed by running:

```bash
python --version
```

On some macOS/Linux systems, use:

```bash
python3 --version
```

---

## 1. Clone the Repository

Open Terminal, PowerShell, or Command Prompt and run:

```bash
git clone https://github.com/MariamRukhaia/CipherSense-Adaptive-Cipher-Selector.git
```

Enter the project directory:

```bash
cd CipherSense-Adaptive-Cipher-Selector
```

---

## 2. Create a Virtual Environment

Creating a virtual environment keeps CipherSense's Python dependencies isolated from other projects.

### macOS / Linux

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

### Windows

```bash
py -m venv .venv
```

Activate it:

```bash
.venv\Scripts\activate
```

After activation, your terminal will typically display `(.venv)` before the command prompt.

---

## 3. Install Dependencies

With the virtual environment activated, run:

```bash
pip install -r requirements.txt
```

The application uses Flask for the web interface.

---

## 4. Verify the Required Files

Before starting the application, make sure the project root contains:

```text
adaptive.py
app.py
Table.csv
```

`Table.csv` is required by the recommendation engine and must remain in the project root unless the paths in the source code are changed.

You should also have:

```text
static/
templates/
```

These directories contain the frontend assets and HTML templates used by Flask.

---

## 5. Run the Application

From the project root, run:

```bash
python app.py
```

If your system uses `python3`:

```bash
python3 app.py
```

The terminal should display a local address similar to:

```text
http://127.0.0.1:5000
```

Open that address in your browser.

CipherSense should now be running locally.

---

## 6. Using CipherSense

Once the application opens:

1. Explore the available block ciphers on the home page.
2. Click a cipher to inspect its characteristics.
3. Select **Start the Questionnaire**.
4. Answer each question based on your security and deployment requirements.
5. CipherSense dynamically narrows the candidate pool.
6. Review the final ranked cipher recommendations and their technical properties.

---

## 💻 Command-Line Version

The underlying adaptive selector can also be used without the Flask interface.

Run:

```bash
python adaptive.py
```

or:

```bash
python3 adaptive.py
```

Answer each question by entering the corresponding option number.

The program will evaluate your requirements and display the recommended cipher candidates directly in the terminal.

---

## 🛑 Stopping the Application

Return to the terminal where Flask is running and press:

```text
Ctrl + C
```

To exit the virtual environment afterward, run:

```bash
deactivate
```

---

## 🔧 Troubleshooting

### `ModuleNotFoundError: No module named 'flask'`

Make sure your virtual environment is activated and run:

```bash
pip install -r requirements.txt
```

### `FileNotFoundError: Table.csv`

Make sure you are running `app.py` from the repository root and that `Table.csv` is located alongside it:

```text
app.py
adaptive.py
Table.csv
```

### Port 5000 is already in use

Another application may already be using Flask's default port.

Stop the other process or run the Flask application on another available port.

---

## 🔬 Cipher Evaluation Criteria

The cipher knowledge base evaluates algorithms across multiple dimensions, including:

| Property | Purpose |
|---|---|
| Security Level | Estimates overall cryptographic strength |
| Key Size | Evaluates available key lengths |
| Block Size | Helps determine suitability for data volume |
| Processing Time | Represents performance characteristics |
| Low-Power Suitability | Identifies options for constrained devices |
| Standardization | Indicates whether an algorithm is standardized |
| TLS / VPN | Evaluates network-security suitability |
| Storage | Evaluates encryption-at-rest suitability |
| Streaming | Evaluates high-throughput use |
| Hardware Acceleration | Considers hardware optimization |
| Known Attacks | Provides relevant security limitations |


## 👥 Authors

**Mariam Rukhaia**  
**Dhwaj Vachhani**

Developed as an applied cryptography project focused on making block-cipher selection more understandable and accessible to non-expert users.
