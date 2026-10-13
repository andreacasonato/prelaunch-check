import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";

/** Changes to "Copied" with a check for 2 s and announces it politely (Design Brief §4.5). */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const [message, setMessage] = useState("");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setMessage("Copied to clipboard");
    } catch {
      setMessage("Couldn't copy: select the text and copy it manually");
    }
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      setCopied(false);
      setMessage("");
    }, 2000);
  };
  return (
    <>
      <button type="button" className="btn btn-quiet" onClick={copy}>
        {copied ? <Check size={16} aria-hidden /> : <Copy size={16} aria-hidden />}
        {copied ? "Copied" : label}
      </button>
      <span className="visually-hidden" aria-live="polite">
        {message}
      </span>
    </>
  );
}
