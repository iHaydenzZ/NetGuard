import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

function App() {
  const [greetMsg, setGreetMsg] = useState("");
  const [name, setName] = useState("");

  async function greet() {
    setGreetMsg(await invoke("greet", { name }));
  }

  return (
    <main className="min-h-screen bg-gray-900 text-white flex flex-col items-center justify-center p-8">
      <h1 className="text-4xl font-bold mb-8">NetGuard</h1>
      <p className="text-gray-400 mb-6">Network Traffic Monitor & Bandwidth Controller</p>

      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          greet();
        }}
      >
        <input
          className="px-4 py-2 rounded bg-gray-800 border border-gray-600 text-white"
          onChange={(e) => setName(e.currentTarget.value)}
          placeholder="Enter a name..."
        />
        <button
          type="submit"
          className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 transition-colors"
        >
          Greet
        </button>
      </form>
      {greetMsg && <p className="mt-4 text-green-400">{greetMsg}</p>}
    </main>
  );
}

export default App;
