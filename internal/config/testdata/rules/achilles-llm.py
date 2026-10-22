import os
import subprocess
import sqlite3

import anthropic
from openai import OpenAI
from langchain_openai import ChatOpenAI
from langchain_experimental.tools import PythonREPLTool
from langchain_community.agent_toolkits.load_tools import load_tools
from transformers import AutoModelForCausalLM

client = OpenAI()
claude = anthropic.Anthropic()


def run_generated(question):
    resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": question}])
    code = resp.choices[0].message.content
    # ruleid: achilles.llm.python.output-to-code-execution
    exec(code)


def shell_from_claude(task):
    msg = claude.messages.create(model="m", max_tokens=100, messages=[{"role": "user", "content": task}])
    cmd = msg.content[0].text
    # ruleid: achilles.llm.python.output-to-code-execution
    os.system(cmd)
    # ruleid: achilles.llm.python.output-to-code-execution
    subprocess.run(cmd, shell=True)
    # ok: achilles.llm.python.output-to-code-execution
    subprocess.run(["echo", cmd])


def langchain_eval(q):
    llm = ChatOpenAI(model="m")
    answer = llm.invoke(q).content
    # ruleid: achilles.llm.python.output-to-code-execution
    eval(answer)


def text_to_sql(q):
    db = sqlite3.connect("app.db")
    resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": q}])
    sql = resp.choices[0].message.content
    # ruleid: achilles.llm.python.output-to-sql
    db.execute(sql)
    name = resp.choices[0].message.content
    # ok: achilles.llm.python.output-to-sql
    db.execute("SELECT * FROM users WHERE name = ?", (name,))


def not_model_output(user_code):
    # ok: achilles.llm.python.output-to-code-execution
    exec(compile("1 + 1", "<s>", "eval"))
    # ok: achilles.llm.python.output-to-code-execution
    print(user_code)


def tools():
    # ruleid: achilles.llm.python.agent-runs-code
    repl = PythonREPLTool()
    # ruleid: achilles.llm.python.agent-runs-code
    more = load_tools(["llm-math", "terminal"])
    # ruleid: achilles.llm.python.agent-runs-code
    chain = SQLDatabaseChain.from_llm(None, None, allow_dangerous_code=True)
    # ok: achilles.llm.python.agent-runs-code
    safe = load_tools(["llm-math", "wikipedia"])
    return repl, more, chain, safe


def load_model():
    # ruleid: achilles.llm.python.trust-remote-code
    a = AutoModelForCausalLM.from_pretrained("org/model", trust_remote_code=True)
    # ok: achilles.llm.python.trust-remote-code
    b = AutoModelForCausalLM.from_pretrained("org/model", revision="3f2a1c0", trust_remote_code=True)
    # ok: achilles.llm.python.trust-remote-code
    c = AutoModelForCausalLM.from_pretrained("org/model")
    return a, b, c
