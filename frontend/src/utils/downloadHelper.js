/**
 * Safe client-side file downloader that avoids race conditions with URL.revokeObjectURL
 */
export function triggerFileDownload(blob, filename) {
  if (!blob) return;
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    if (a.parentNode) {
      a.parentNode.removeChild(a);
    }
    window.URL.revokeObjectURL(url);
  }, 1500);
}
