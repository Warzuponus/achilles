const { exec } = require("child_process");
const OpenAI = require("openai");
const { ChatOpenAI } = require("@langchain/openai");
const DOMPurify = require("dompurify");

const client = new OpenAI();

async function runIt(task) {
  const resp = await client.chat.completions.create({ model: "m", messages: [{ role: "user", content: task }] });
  const cmd = resp.choices[0].message.content;
  // ruleid: achilles.llm.javascript.output-to-code-execution
  exec(cmd);
  // ruleid: achilles.llm.javascript.output-to-code-execution
  eval(cmd);
  // ok: achilles.llm.javascript.output-to-code-execution
  console.log(cmd);
}

async function render(el, q) {
  const { text } = await generateText({ model: "m", prompt: q });
  // ruleid: achilles.llm.javascript.output-to-html
  el.innerHTML = text;
  // ok: achilles.llm.javascript.output-to-html
  el.innerHTML = DOMPurify.sanitize(text);
  // ok: achilles.llm.javascript.output-to-html
  el.textContent = text;
}

async function chain(el, q) {
  const llm = new ChatOpenAI({ model: "m" });
  const out = await llm.invoke(q);
  // ruleid: achilles.llm.javascript.output-to-html
  el.insertAdjacentHTML("beforeend", out.content);
}

function notModel(el, s) {
  // ok: achilles.llm.javascript.output-to-html
  el.innerHTML = "<b>" + "static" + "</b>";
}
