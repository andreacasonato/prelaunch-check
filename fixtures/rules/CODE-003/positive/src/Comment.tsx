export function Comment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function render(el: HTMLElement, value: string) {
  el.innerHTML = value;
}
