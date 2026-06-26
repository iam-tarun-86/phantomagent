import { useState, useEffect } from 'react';

export const useTypewriter = (text, speed = 30, startTyping = true) => {
    const [displayedText, setDisplayedText] = useState('');
    const [isComplete, setIsComplete] = useState(false);

    useEffect(() => {
        if (!startTyping || !text) {
            setDisplayedText('');
            setIsComplete(false);
            return;
        }

        setDisplayedText('');
        setIsComplete(false);

        let index = 0;
        const timer = setInterval(() => {
            if (index < text.length) {
                setDisplayedText(text.slice(0, index + 1));
                index++;
            } else {
                setIsComplete(true);
                clearInterval(timer);
            }
        }, speed);

        return () => clearInterval(timer);
    }, [text, speed, startTyping]);

    return { displayedText, isComplete };
};