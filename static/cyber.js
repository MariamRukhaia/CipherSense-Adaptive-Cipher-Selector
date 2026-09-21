document.addEventListener("DOMContentLoaded", () => {
    document.body.style.opacity = 0;
    setTimeout(() => {
        document.body.style.transition = "opacity 0.7s ease-out";
        document.body.style.opacity = 1;
    }, 100);
});


function scrollToSection(id) {
    document.getElementById(id).scrollIntoView({ behavior: 'smooth' });
}

function openCipherModal(name) {
    const cipherData = window.cipherInfo[name];
    document.getElementById('cipherTitle').textContent = name;
    document.getElementById('cipherDetails').innerHTML =
        cipherData.desc.replace(/\n/g, "<br>");
    document.getElementById('cipherLink').href = cipherData.link;

    document.getElementById('cipherModal').style.display = 'flex';
}

function closeCipherModal(event) {
    if (event.target.classList.contains("modal-overlay") || 
        event.target.classList.contains("close-btn")) {
        document.getElementById('cipherModal').style.display = 'none';
    }
}

function toggleExtra() {
    const div = document.getElementById("extra-results");
    if (div.style.display === "none") {
        div.style.display = "block";
    } else {
        div.style.display = "none";
    }
}
