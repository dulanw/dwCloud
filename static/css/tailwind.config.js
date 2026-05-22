module.exports = {
    darkMode: 'class', // Enable dark mode using the 'class' strategy (alternatively, use 'media')
    content: [
        "./template/**/*.{templ,html}",
        "./component/**/*.{templ,html}",
        "./**/*.go",
    ],
    theme: {
        extend: {
            // Any custom theme settings (optional)
        },
    },
};