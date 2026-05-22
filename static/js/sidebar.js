/*
* credits to https://github.com/lukewilliamboswell/roc-htmx-tailwindcss-demo
*/

function updateSidebar(element) {
    Array.from(
        document.getElementsByClassName("sidebar-button-link"),
    ).forEach((el) => {
        el.classList.remove("bg-gray-100");
        el.classList.remove("dark:bg-gray-700");
    });

    element.classList.add("bg-gray-100");
    element.classList.add("dark:bg-gray-700");
}