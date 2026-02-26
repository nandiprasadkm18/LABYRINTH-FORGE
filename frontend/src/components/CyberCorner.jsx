export default function CyberCorner({ className = "", position = "top-left" }) {
    const corners = {
        'top-left': 'top-0 left-0',
        'top-right': 'top-0 right-0 rotate-90',
        'bottom-left': 'bottom-0 left-0 -rotate-90',
        'bottom-right': 'bottom-0 right-0 rotate-180',
    };
    return (
        <svg
            className={`absolute w-8 h-8 ${corners[position]} ${className} z-10 opacity-60 pointer-events-none`}
            viewBox="0 0 32 32" fill="none"
        >
            <path d="M0 2V0H32V2H2V32H0V2Z" fill="currentColor" />
        </svg>
    );
}
