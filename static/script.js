async function checkStrength() {
  const password = document.getElementById("password").value;
  const bar = document.getElementById("bar");
  const text = document.getElementById("strength-text");
  const suggestions = document.getElementById("suggestions");

  if (password.length === 0) {
    bar.style.width = "0%";
    text.textContent = "";
    suggestions.innerHTML = "";
    return;
  }

  const response = await fetch("/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });

  const data = await response.json();

  // Update strength bar width
  let width = "0%";
  if (data.strength === "Weak") {
    width = "33%";
  } else if (data.strength === "Medium") {
    width = "66%";
  } else {
    width = "100%";
  }

  bar.style.width = width;

  // Display AI feedback and entropy info
  text.innerHTML = `
    <strong>Strength:</strong> ${data.strength} <br>
    <small>${data.ai_msg}</small>
  `;

  // Display suggestions & breach info
  if (data.pwned) {
    suggestions.innerHTML = `
      <li style="color:red;">⚠️ Found in ${data.pwned_count} known breaches. Avoid using this password!</li>
      ${data.remarks.map(r => `<li>${r}</li>`).join("")}
    `;
  } else {
    suggestions.innerHTML = data.remarks.map(r => `<li>${r}</li>`).join("");
  }
}
