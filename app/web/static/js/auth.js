/**
 * Firebase Auth — sign in, session exchange with backend.
 */
(function () {
    const emailForm = document.getElementById('email-form');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const emailSignInBtn = document.getElementById('email-signin-btn');
    const googleSignInBtn = document.getElementById('google-signin-btn');
    const toggleRegister = document.getElementById('toggle-register');
    const authMessage = document.getElementById('auth-message');

    let isRegisterMode = false;

    function showMessage(text, type) {
        authMessage.textContent = text;
        authMessage.className = 'auth-message ' + (type || '');
        authMessage.style.display = 'block';
    }

    function hideMessage() {
        authMessage.style.display = 'none';
    }

    function setLoading(loading) {
        emailSignInBtn.disabled = loading;
        googleSignInBtn.disabled = loading;
        emailSignInBtn.textContent = loading ? 'Signing in…' : (isRegisterMode ? 'Create Account' : 'Sign In');
    }

    async function exchangeToken(idToken) {
        const res = await fetch('/api/session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ idToken }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            const msg = data.error || (res.status === 401 ? 'Please sign in again.' : 'Session error');
            const err = new Error(msg);
            err.code = data.code;
            err.status = res.status;
            throw err;
        }
        return data;
    }

    // Email/password sign in or register
    emailForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideMessage();
        setLoading(true);
        try {
            if (isRegisterMode) {
                await auth.createUserWithEmailAndPassword(emailInput.value.trim(), passwordInput.value);
            } else {
                await auth.signInWithEmailAndPassword(emailInput.value.trim(), passwordInput.value);
            }
            const user = auth.currentUser;
            const idToken = await user.getIdToken();
            const data = await exchangeToken(idToken);
            showMessage('Signed in successfully.', 'success');
            const nextUrl = (data && data.next) ? data.next : '/';
            setTimeout(() => { window.location.href = nextUrl; }, 400);
        } catch (err) {
            const msg = err.message || 'Sign in failed';
            showMessage(msg, 'error');
        } finally {
            setLoading(false);
        }
    });

    // Google sign in
    googleSignInBtn.addEventListener('click', async () => {
        hideMessage();
        setLoading(true);
        try {
            const provider = new firebase.auth.GoogleAuthProvider();
            await auth.signInWithPopup(provider);
            const user = auth.currentUser;
            const idToken = await user.getIdToken();
            const data = await exchangeToken(idToken);
            showMessage('Signed in with Google.', 'success');
            const nextUrl = (data && data.next) ? data.next : '/';
            setTimeout(() => { window.location.href = nextUrl; }, 400);
        } catch (err) {
            showMessage(err.message || 'Google sign in failed', 'error');
        } finally {
            setLoading(false);
        }
    });

    // Toggle sign in / register
    toggleRegister.addEventListener('click', (e) => {
        e.preventDefault();
        isRegisterMode = !isRegisterMode;
        emailSignInBtn.textContent = isRegisterMode ? 'Create Account' : 'Sign In';
        toggleRegister.textContent = isRegisterMode ? 'Already have an account? Sign in' : 'Create account';
    });
})();
