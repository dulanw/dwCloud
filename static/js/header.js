function makeDark() {
    document.documentElement.classList.add("dark");
    document
        .getElementById("theme-toggle-light-icon")
        ?.classList.remove("hidden");
    document
        .getElementById("theme-toggle-dark-icon")
        ?.classList.add("hidden");
}

function makeLight() {
    document.documentElement.classList.remove("dark");
    document
        .getElementById("theme-toggle-dark-icon")
        ?.classList.remove("hidden");
    document
        .getElementById("theme-toggle-light-icon")
        ?.classList.add("hidden");
}

function toggleDarkMode() {
    if (document.documentElement.classList.contains("dark")) {
        makeLight();
        localStorage.setItem("color-theme", "light");
    } else {
        makeDark();
        localStorage.setItem("color-theme", "dark");
    }
}

function setDarkMode() {
    if (
        localStorage.getItem("color-theme") === "dark" ||
        (!("color-theme" in localStorage) &&
            window.matchMedia("(prefers-color-scheme: dark)").matches)
    ) {
        makeDark();
    } else {
        makeLight();
    }
}

function handleResize() {
    if (window.innerWidth >= 1024) {
        document
            .getElementById("sidebar-content")
            ?.classList.remove("hidden");
    } else {
        document.getElementById("sidebar-content")?.classList.add("hidden");
    }
}

document.addEventListener("htmx:afterSettle", function (evt) {
    setDarkMode();
});

document.addEventListener("DOMContentLoaded", function () {
    setDarkMode();
    handleResize();
});

window.addEventListener("resize", handleResize);