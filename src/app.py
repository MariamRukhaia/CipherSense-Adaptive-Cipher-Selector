from flask import Flask, render_template, request, session
from adaptive import compute_step  
import csv, json, random

app = Flask(__name__)
app.secret_key = "123"  

@app.route("/")
def index():
    with open("Table.csv", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    cipher_info = {row["NAME"]: {
                    "desc": f"""
                        Structure: {row["STRUCTURE"]}
                        Security: {row["SECURITY/STRENGTH LEVEL"]}
                        Block Size: {row["BLOCK SIZE (bits)"]}
                        Common Use: {row["COMMON USE"]}
                    """,
                    "link": row["Sources"].strip() }
                    for row in rows}


    shuffled_rows = []
    for i in range(3):   
        copy_list = rows[:]        
        random.shuffle(copy_list)  
        shuffled_rows.append(copy_list)

    return render_template("index.html",
                            ciphers=rows,
                            shuffled_rows=shuffled_rows,
                            cipher_info=json.dumps(cipher_info))



@app.route("/wizard", methods=["GET", "POST"])
def wizard():
    if request.method == "GET":
        session.pop("answers", None)   
        session.pop("candidate_list", None)
        session.pop("step", None)

    answers = session.get("answers", {})

    if request.method == "POST":
        qid = request.form["qid"]
        ans_idx = int(request.form["answer"])
        answers[qid] = ans_idx
        session["answers"] = answers

    result = compute_step(answers)

    if result["done"]:
        return render_template("results.html",
                               results=result["results"],
                               constraints=result["constraints"],
                               all_candidates=result.get("all_candidates", []))

    question = result["next_question"]
    return render_template("question.html",
                           qid=question["qid"],
                           prompt=question["prompt"],
                           options=question["options"],
                           candidate_count=result.get("candidate_count"))


if __name__ == "__main__":
    app.run(debug=True)
