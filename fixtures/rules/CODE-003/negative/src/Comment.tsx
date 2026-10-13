import DOMPurify from "dompurify";

export function Comment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function clear(el: HTMLElement) {
  el.innerHTML = "";
  if (el.innerHTML === "x") return;
}
