document.addEventListener('DOMContentLoaded', function () {
    //GLOBAL VAR FOR SWITCHING BETWEEN DEV AND PROD IN REQUESTS.
    // change the link between dev and prod. Add the php file to request to end of url in *your own* fetch call
    let fetchUrl = 'https://se-prod.cse.buffalo.edu/CSE442/2025-Spring/cse-442l/src/backend';
    let imgfetchUrl = 'https://se-prod.cse.buffalo.edu/CSE442/2025-Spring/cse-442l';

    //Each request requiring **CSRF** authentication MUST call this function in order to perform fetch properly
    //Method MUST be POST. CSRF Tokens for GET requests is insecure
    //path should be the "/{backend_filename}.php" page to be requested- Ex: "/login.php", "/register.php"
    //Returns Response PROMISE- Use the .then(response => {...}) stuff to capture it.
    function authRequest(path, payload) {
        //Get csrf token from session storage- only the ORIGIN can read it anyway
        const csrf_token = sessionStorage.getItem('csrf_token');
        return fetch(fetchUrl + path, {
            credentials: 'include',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrf_token,
            },
            body: JSON.stringify(payload),
        }).then(response => {
            if (response.ok) {
                return response.json();
            }
        })
    }

    //Similar to authRequest , but using formData in order to accomadate file uploading, as json file objects cannot be stringified directly,
    function authFileRequest(path, jsonPayload, filepayload) {
        const csrf_token = sessionStorage.getItem('csrf_token');
        const formData = new FormData();

        // Add JSON under the 'json' field
        formData.append("json", JSON.stringify(jsonPayload));

        // Add file if provided
        if (filepayload) {
            formData.append("fileToUpload", filepayload);
        }

        return fetch(fetchUrl + path, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'X-CSRF-Token': csrf_token
                // DO NOT set Content-Type here! Let the browser handle it.
            },
            body: formData
        }).then(response => {
            if (response.ok) {
                return response.json();
            }
        });
    }

    //For multipart requests. Browser will set the content-type
    function authRequestMulti(path, payload) {
        const csrf_token = sessionStorage.getItem('csrf_token');
        return fetch(fetchUrl + path, {
            credentials: 'include',
            method: 'POST',
            headers: {
                'X-CSRF-Token': csrf_token,
            },
            body: payload,
        }).then(response => {
            if (response.ok) {
                return response.json();
            }
        })
    }

    //Load login page
    const login = document.getElementById("login-button");
    if (login) {
        login.addEventListener("click", function () {
            document.getElementById("landing-page").style.display = "none";
            document.getElementById("landing-page").style.visibility = "hidden";
            document.getElementById("login-page").style.display = "block";
            document.getElementById("login-page").style.visibility = "visible";
        });
    }
    //Load Landing Page
    const back = document.getElementById("back-arrow");
    if (back) {
        back.addEventListener("click", function () {
            document.getElementById("login-page").style.display = "none";
            document.getElementById("login-page").style.visibility = "hidden";
            document.getElementById("landing-page").style.display = "block";
            document.getElementById("landing-page").style.visibility = "visible";
        });
    }

    //Load register Page
    document.getElementById("signup-button").addEventListener("click", function () {
        document.getElementById("landing-page").style.display = "none";
        document.getElementById("landing-page").style.visibility = "hidden";
        document.getElementById("register-page").style.display = "block";
        document.getElementById("register-page").style.visibility = "visible";
    })

    //Load Landing Page from register page
    document.getElementById("back-arrowRegister").addEventListener("click", function () {
        document.getElementById("register-page").style.display = "none";
        document.getElementById("register-page").style.visibility = "hidden";
        document.getElementById("landing-page").style.display = "block";
        document.getElementById("landing-page").style.visibility = "visible";
    })

    // Load Forgot Password Page from login
    document.getElementById("forgot-password-button").addEventListener("click", function () {
        document.getElementById("login-page").style.display = "none";
        document.getElementById("login-page").style.visibility = "hidden";
        document.getElementById("forgot-password-page").style.display = "block";
        document.getElementById("forgot-password-page").style.visibility = "visible";
    });

    // Back to landing page from Forgot Password Page
    document.getElementById("back-to-login").addEventListener("click", function () {
        document.getElementById("forgot-password-page").style.display = "none";
        document.getElementById("forgot-password-page").style.visibility = "hidden";
        document.getElementById("login-page").style.display = "block";
        document.getElementById("login-page").style.visibility = "visible";
    });

    // Move to Security Question Page after entering username
    document.getElementById("security-question-button").addEventListener("click", function () {
        const username = document.getElementById("forgot-username").value;
        const data = {username: username};

        //Check for no username entered or too long
        if (username.length === 0) {
            document.getElementById("forgot-error").innerHTML = "Username cannot be empty.";
            return;
        }

        fetch(fetchUrl + '/retrieveQuestion.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        })
            .then(response => response.json())
            .then(response => {
                if (response.status.toString() !== 'failure') {
                    const question = response.question;
                    const securityQuestions = [" ", "Favorite Teachers Name?", "Most Hated Person?", "Favourite family member?"]

                    document.getElementById("security-question-text").innerText = securityQuestions[question];
                    document.getElementById("forgot-password-page").style.display = "none";
                    document.getElementById("forgot-password-page").style.visibility = "hidden";
                    document.getElementById("security-question-page").style.display = "block";
                    document.getElementById("security-question-page").style.visibility = "visible";
                } else {
                    document.getElementById("forgot-error").innerHTML = "Invalid Username.";
                }
            })

    });

    // Back arrow  to forgot password page from security question page
    document.getElementById("back-to-forgot").addEventListener("click", function () {

        document.getElementById("security-question-page").style.display = "none";
        document.getElementById("security-question-page").style.visibility = "hidden";
        document.getElementById("forgot-password-page").style.display = "block";
        document.getElementById("forgot-password-page").style.visibility = "visible";
    });

    //Move to actual password reset page after username and security question is answered
    document.getElementById("submit-security-answer").addEventListener("click", function () {
        const username = document.getElementById("forgot-username").value
        const answer = document.getElementById("security-answer").value;
        const data = {username: username, answer: answer}

        if (answer.length === 0) {
            document.getElementById("security-error").innerHTML = "Answer cannot be empty.";
            return;
        }

        fetch(fetchUrl + '/verifyAnswer.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data),
        })
            .then(response => response.json())
            .then(data => {
                if (data.status === "success") {
                    document.getElementById("security-question-page").style.display = "none";
                    document.getElementById("security-question-page").style.visibility = "hidden";
                    document.getElementById("password-reset-page").style.display = "block";
                    document.getElementById("password-reset-page").style.visibility = "visible";
                } else {
                    document.getElementById("security-error").innerHTML = "Incorrect answer. Try again.";
                }

            })

    });

    // Back to Security question page from reset  password page
    document.getElementById("back-to-security").addEventListener("click", function () {

        document.getElementById("password-reset-page").style.display = "none";
        document.getElementById("password-reset-page").style.visibility = "hidden";
        document.getElementById("security-question-page").style.display = "block";
        document.getElementById("security-question-page").style.visibility = "visible";
    });

    //Check for correct new password entered then move back to the login page
    document.getElementById("submit-new-password").addEventListener("click", function () {

        const username = document.getElementById("forgot-username").value
        const answer = document.getElementById("security-answer").value;
        const newPassword = document.getElementById("new-password").value;
        const confirmPassword = document.getElementById("confirm-password").value;
        data = {username: username, answer: answer, password: newPassword}

        if (newPassword.length === 0) {
            document.getElementById("password-error").innerHTML = "Answer cannot be empty!";
            return;
        }

        if (newPassword != confirmPassword) {
            document.getElementById("password-error").innerHTML = "Passwords do not match!";
            return;
        }

        fetch(fetchUrl + '/changePassword.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data),
        })
            .then(response => response.json())
            .then(data => {
                if (data.status === "success") {
                    document.getElementById("password-reset-page").style.display = "none";
                    document.getElementById("password-reset-page").style.visibility = "hidden";
                    document.getElementById("login-page").style.display = "block";
                    document.getElementById("login-page").style.visibility = "visible";
                } else {
                    document.getElementById("password-error").innerHTML = "Error resetting password.";
                }

            });
    });

    //Sending POST request to login
    const loginButton = document.getElementById('login');
    if (loginButton) {
        loginButton.addEventListener('click', function (event) {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const data = {username: username, password: password};

            //Front end **user experience** check
            if (username.length <= 0 || password.length <= 0) {
                document.getElementById('error').innerHTML = "Inputs cannot be empty";
            } else if (username.length > 25 || password.length > 25) {
                document.getElementById('error').innerHTML = "Inputs must be 25 characters or less";
            }

            //Send request
            fetch(fetchUrl + '/login.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include', //Getting cookie
                body: JSON.stringify(data),
            }).then(response => response.json())
                .then(response => {
                    if (response.status !== 'failure') {
                        //Store CSRF token into session storage on login + username/id for ez post requests
                        sessionStorage.setItem('csrf_token', response.csrf_token);
                        sessionStorage.setItem('user_id', response.user_data['id']);
                        sessionStorage.setItem('username', response.user_data['username']);
                        createVault();
                    } else {
                        document.getElementById('error').innerHTML = "Incorrect username or password";
                    }
                });
        });
    }

    //Sending POST request to register
    const signUpButton = document.getElementById('signUP-button')
    signUpButton.addEventListener('click', function (event) {

        const username = document.getElementById('input-usernameReg').value;
        const email = document.getElementById('input-email').value;
        const password = document.getElementById('input-passwordReg').value;
        const securityQuestion = document.getElementById('menu1').value;
        const question_response = document.getElementById('question-response').value;
        const data = {
            username: username,
            password: password,
            email: email,
            question: securityQuestion,
            answer: question_response
        };
        if (question_response.length <= 0) {
            document.getElementById('question-error').innerHTML = "Input cannot be empty";
        } else if (securityQuestion === "prompt") {  // Check if default option is selected
            document.getElementById('question-error').innerHTML = "Please select a security question.";
        }
        //Send request
        else {
            fetch(fetchUrl + '/security_questions.php', {
                credentials: 'include', //getting cookie
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            })
                .then(response => response.json())  // Capture the HTTP response
                .then(response => {
                    if ((response.status.toString() !== 'failure') || (response.status.toString() !== 'error')) {
                        //set CSRFToken on successful login
                        sessionStorage.setItem('csrf_token', response.csrf_token);
                        sessionStorage.setItem('user_id', response.user_data['id']);
                        sessionStorage.setItem('username', response.user_data['username']);
                        createVault();
                    } else {
                        document.getElementById('question-error').innerHTML = `Error: ${response.errors.toString()}`;
                    }

                })
                .catch((error) => {
                    console.error('Error:', error);
                    // document.getElementById('error').innerHTML = `Error: ${error.message}`;
                });

        }
    });

    //Sending POST request to register
    const continueButton = document.getElementById('continue-button')
    continueButton.addEventListener('click', function (event) {
        const username = document.getElementById('input-usernameReg').value;
        const email = document.getElementById('input-email').value;
        const password = document.getElementById('input-passwordReg').value;
        const verifyPassword = document.getElementById('input-verifyPassword').value;
        const data = {username: username, password: password, email: email, verify_password: verifyPassword};

        if (username.length <= 0 || email.length <= 0 || password.length <= 0 || verifyPassword.length <= 0) {
            document.getElementById('register-error').innerHTML = "Inputs cannot be empty";
        } else if (username.length > 25 || password.length > 25 || verifyPassword.length > 25) {
            document.getElementById('register-error').innerHTML = "Inputs must be 25 characters or less";
        } else if (email.length > 35) {
            document.getElementById('register-error').innerHTML = "Inputs must be 25 characters or less";
        }
        //Send request
        else {
            fetch(fetchUrl + '/register.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            })
                .then(response => response.json())  // Capture the HTTP response
                .then(response => {
                    if (response.status.toString() !== "failure") {
                        document.getElementById("landing-page").style.display = "none";
                        document.getElementById("landing-page").style.visibility = "hidden";
                        document.getElementById("register-page").style.display = "none"
                        document.getElementById("register-page").style.visibility = "hidden"
                        document.getElementById("SecurityQ-page").style.display = "block";
                        document.getElementById("SecurityQ-page").style.visibility = "visible";
                    } else {
                        document.getElementById('register-error').innerHTML = `Error: ${response.errors.toString()}`;
                    }
                })
                .catch((error) => {
                    console.error('Error:', error);
                    //document.getElementById('error').innerHTML = `Error: ${error.message}`;
                });

        }

    });

    //Load login Page from  SecurityQ page
    document.getElementById("back-arrowSecurityQ").addEventListener("click", function () {
        document.getElementById("SecurityQ-page").style.display = "none";
        document.getElementById("SecurityQ-page").style.visibility = "hidden";
        document.getElementById("register-page").style.display = "block";
        document.getElementById("register-page").style.visibility = "visible";
    });


    //--------------------------------Vault Page Functionality --------------------------------//

    //Adding an account
    function clickAdd(event) {
        document.body.innerHTML = "<div id='password-generator-container'></div><div class='container text-center py-0 m-0' id='create-page'><div class='container p-3 pb-4'><div class='row d-flex align-items-center'><div class='col-2 p-0'><div class='text-start' id='back-arrow'><i role='button' class='fa-solid fa-arrow-left' style='font-size: 1.25rem;'></i></div></div><div class='col-7 p-0' style='font-size: 1.15rem;'><div class='fw-bold'>New Entry</div></div><div class='col-3 p-0'><div id='save-button' role='button' class='btn w-100 p-1'>Save</div></div></div></div><div class='container p-0'><form enctype='multipart/form-data' class='w-100'><div class='row d-flex align-content-center'><div class='col-4 pe-0 align-content-center'><div role='button' class='bg-light rounded border border-dark' style='height: 99px;'><label for='add-icon' class='h-100 w-100 align-content-center' style='cursor: pointer;'><p id='img-loc' class='m-0'>+</p><input id='add-icon' type='file' accept='.jpg, .png, .jpeg' style='display: none;'/></label></div></div><div class='col-8 align-content-center'><div class='row pb-2'><div class='col'><label for='add-platform' class='w-100'><input id='add-platform' type='text' placeholder='Website Name' maxlength='25' class='w-100 form-control rounded' value=''/></label></div></div><div class='row'><div class='col'><label for='add-username' class='w-100'><input id='add-username' type='text' placeholder='Username/email' maxlength='25' class='w-100 form-control rounded' value=''/></label></div></div></div></div><hr><div class='text-start p-0 m-0'><p class='mb-1'>Password:</p><div class='row'><div class='col-10'><label for='add-password' class='w-100'><input id='add-password' type='password' placeholder='Password' maxlength='129' class='w-100 form-control rounded' value=''/></label></div><div class='col-2 ps-0 py-0'><div role='button' class='btn p-1' style='width: 39px; font-size: 1rem;' id='eye-icon-add'><i class='fa-regular fa-eye'></i></div></div></div></div></form></div></div><div class='modal hidden' id='exampleModal'><div class='modal-container'><div class='row mb-2'><div class='col-9 fw-bold'>Error Submitting</div><div class='col-3'><button type='button' class='btn-close' id='modal-close'></button></div></div><hr class='m-0'><p id='modal-msg' class='text-center my-2' style='font-size: 1rem;'></p></div></div>";
        loadPasswordGenerator();
        const eyecon = document.getElementById('eye-icon-add');
        const back = document.getElementById('back-arrow');
        const uploadImage = document.getElementById("add-icon");
        const imgLoc = document.getElementById('img-loc');
        const saveAdd = document.getElementById('save-button');
        let passtext = document.getElementById('add-password');
        const modal = document.getElementById("exampleModal");
        const modalMessage = document.getElementById('modal-msg');
        const modalExit = document.getElementById('modal-close');
        //reveal password
        if (eyecon) {
            eyecon.addEventListener('click', function (event) {
                if (passtext.type === 'text') {
                    passtext.type = 'password';
                } else {
                    passtext.type = 'text';
                }
            })
        }
        //Return to Vault Page
        if (back) {
            back.addEventListener('click', function (event) {
                createVault();
            })
        }
        //Render image to USER to confirm they've chosen the correct img
        let filedata = "";
        if (uploadImage) {
            uploadImage.addEventListener('change', function () {
                if (this.files && this.files[0]) {
                    filedata = this.files[0];
                    var reader = new FileReader();
                    reader.onload = function (e) {
                        imgLoc.innerHTML = "<img src='" + e.target.result + "'>"
                    };
                    reader.readAsDataURL(this.files[0]);
                }
            });
        }
        //Submit created account
        if (saveAdd) {
            saveAdd.addEventListener('click', function () {
                //USER EXPERIENCE CHECK. Error when inputs are empty
                const addPlatform = document.getElementById('add-platform').value;
                const addUsername = document.getElementById('add-username').value;
                if (addPlatform.length <= 0 || addUsername.length <= 0 || passtext.value.length <= 0) {
                    modalMessage.innerHTML = "To save the entry, a website name, username, and password must be present.";
                    modal.className = "modal";
                }
                else if (addPlatform.length > 25 || addUsername.length > 25 || passtext.value.length > 25){
                    modalMessage.innerHTML = "Website name, username, and password must be less than 25 characters";
                    modal.className = "modal";
                }
                if (filedata.length !== 0 && (filedata.type.toString() !== "image/jpeg" && filedata.type.toString() !== "image/png")) {
                    modalMessage.innerHTML = "Incorrect file type- upload a jpg or png";
                    modal.className = "modal";
                }
                else {
                    const json = new FormData();
                    const jsonData = {
                        id: sessionStorage.getItem("user_id"),
                        accplatform: addPlatform,
                        accusername: addUsername,
                        accpassword: passtext.value
                    };
                    if(filedata.length !== 0){
                        json.set("fileToUpload", filedata);
                    }
                    json.set("json", JSON.stringify(jsonData));
                    authRequestMulti("/create_account.php", json).then(response => {
                        if (response.status.toString() !== "failure") {
                            createVault();
                        } else if (response.message.toString() === "Missing required fields") {
                            modalMessage.innerHTML = "To save the entry, a website name, username, and password must be present.";
                            modal.className = "modal";
                        } else {
                            modalMessage.innerHTML = response.message.toString()
                            modal.className = "modal";
                        }
                    });
                }
            });
        }
        //Close the modal if open
        if (modalExit) {
            modalExit.addEventListener('click', function () {
                modal.className = "modal hidden";
                modalMessage.innerHTML = "";
            });
        }
    }

    //Check Password Strength
    function clickStrength(event) {
        document.body.innerHTML = "<div id='generate-page'><div class='row justify-content-center align-items-center pt-4'><div class='col-2 p-0'><p role='button' class='m-0' id='back-arrow'><i class='fa-solid fa-arrow-left'></i></p></div><h4 class='col-8 m-0 fw-bold text-left'> Password Strength </h4><div class='col-4'></div></div><div class='container px-3 text-center'><div class='text-start pb-2 pt-2' style='font-size: 1.1rem;'>Enter a Password:</div><div id='row' class='row text-start mb-2'><div class='col-10 pe-0'>" +
            "<input id='pass-to-check' type='password' placeholder='Password' min='1' max='128' class='form-control' required/></div><div class='col-2 px-1'><div role='button' class='btn p-0 h-100' style='width: 39px; font-size: 1rem;' id='reveal-eye'><i class='fa-solid fa-eye p-2'></i></div></div></div>" +
            "<div id='error-message' class='text-center text-danger px-2 mt-2' style='display: none;'></div>" +
            "<div id='generate-button' class='btn py-1 px-2 w-100 mt-2'>Check Password Strength</div></div></div>" +
            "<div id='strength-message' class='text-center mt-4' style='display: none;'></div>"

        document.getElementById('back-arrow').addEventListener('click', createVault);

        let pass = document.getElementById('pass-to-check');
        const errormsg = document.getElementById('error-message');
        const strengthmsg = document.getElementById('strength-message');
        const container = document.getElementById('row');
        const submittedPassword = document.getElementById('pass-to-check');

        document.getElementById('reveal-eye').addEventListener('click', function () {
            if (pass.type === "password") {
                pass.type = "text";
            } else {
                pass.type = "password";
            }
        });

        document.getElementById('generate-button').addEventListener("click", function () {
            if (pass.value.length <= 0) {
                errormsg.style.display = "block";
                strengthmsg.style.display = 'none';
                errormsg.innerHTML = "Must enter a password"
                container.className = "row text-start mb-2"
            } else if (pass.value.length > 128) {
                errormsg.style.display = "block";
                strengthmsg.style.display = 'none';
                errormsg.innerHTML = "Password must be less than 129 characters"
                container.className = "row text-start mb-2"
            } else {
                //vvvvv STRENGTHMSG innerHTML must update according to response
                //Weak is the default response before the linking task is implemented
                const data = {"password": submittedPassword.value}
                authRequest('/password_strength.php', data).then(response => {
                    if (response.status === 'success') {
                        errormsg.style.display = "none";
                        strengthmsg.style.display = "block";
                        const result = "Result: " + response.message
                        strengthmsg.innerHTML = "<h2 class='fw-bold'>" + result + "</h2>";
                    } else {
                        strengthmsg.style.display = "none";
                        errormsg.style.display = "block";
                        errormsg.innerHTML = response.message;
                    }
                });
            }

        })
    }

    //Generate Passwords
    function clickGenerate(event) {
        document.body.innerHTML = "<div id='search-page'> <div class='row justify-content-center align-items-center pt-4'> <div class='col-2 ps-0'><p role='button' class='m-0' id='back-arrow'><i class='fa-solid fa-arrow-left'></i></p> </div> <h4 class='col-8 m-0 fw-bold text-left'> Password Generation </h4> <div class='col-4'></div> </div> <div class='container pt-3 px-3 m-0'> <div class='bg-white rounded p-3 text-center mb-3'><div class='row align-items-center mb-3'> <div class='col-8 text-start' style='font-size: 1.05rem;'>Minimum Password Length:</div> <div class='col-4'>" +
            "<input id='min-pass' type='number' placeholder='10' min='1' max='128' class='form-control text-center' required/> </div> </div> <div class='row align-items-center mb-3'> <div class='col-8 text-start' style='font-size: 1.05rem;'>Maximum Password Length:</div> <div class='col-4'>" +
            "<input id='max-pass' type='number' placeholder='10' min='1' max='128' class='form-control text-center' required/> </div></div><div class='row align-items-center mb-3'> <div class='col-8 text-start' style='font-size: 1.05rem;'>Include Uppercase Letters:</div> <div class='col-4'>" +
            "<input id='include-upper' class='form-check-input' type='checkbox'> </div> </div> <div class='row align-items-center mb-3'> <div class='col-8 text-start' style='font-size: 1.05rem;'>Include Lowercase Letters:</div> <div class='col-4'>" +
            "<input id='include-lower' class='form-check-input' type='checkbox'> </div> </div> <div class='row align-items-center mb-3'> <div class='col-8 text-start' style='font-size: 1.05rem;'>Include Numbers:</div> <div class='col-4'>" +
            "<input id='include-num' class='form-check-input' type='checkbox'> </div> </div> <div class='row align-items-center mb-3'> <div class='col-8 text-start' style='font-size: 1.05rem;'>Include Special Characters:</div> <div class='col-4'>" +
            "<input id='include-special' class='form-check-input' type='checkbox'> </div> </div> <div class='row align-items-center'> <div class='col-8 text-start' style='font-size: 1.05rem;'>At Least 1 From Each Group:</div> <div class='col-4'>" +
            "<input id='one-each' class='form-check-input' type='checkbox'> </div></div>  </div> <div class='row align-items-center'> <div class='col-4'> <div id='generate-button' class='btn py-1 px-2 w-100'>Generate</div> </div> <div class='col-8 ps-0'> <input value='' readonly id='generated-password' style='background-color: white;' class='form-control w-100 rounded' type='text' placeholder='Password' maxlength='129'/> </div> </div> </div> </div><div id='error-message' class='text-center text-danger px-2' style='display: none;'></div>"

        document.getElementById('back-arrow').addEventListener('click', function () {
            createVault();
        });

        document.getElementById('generate-button').addEventListener('click', function () {
            const min = document.getElementById('min-pass').value;
            const max = document.getElementById('max-pass').value;
            const num = document.getElementById('include-num').checked;
            const special = document.getElementById('include-special').checked;
            const oneEach = document.getElementById('one-each').checked;
            const upper = document.getElementById('include-upper').checked;
            const lower = document.getElementById('include-lower').checked;

            const data = {
                'id': sessionStorage.getItem('user_id'),
                'min': min,
                'max': max,
                'upper': upper,
                'lower': lower,
                'Numbers': num,
                'Special': special,
                'OneEach': oneEach,
            }

            //User experience stuff
            const errorDiv = document.getElementById('error-message');
            if (parseInt(min) <= 0 || min.length === 0) {
                errorDiv.innerHTML = "Minimum password length must be greater than or equal to 0"
                errorDiv.style.display = 'block';
            } else if (parseInt(min) > parseInt(max) || max.length === 0) {
                errorDiv.innerHTML = "Minimum length cannot be greater than maximum length";
                errorDiv.style.display = 'block';
            } else if (parseInt(min) > 128 || parseInt(max) > 128) {
                errorDiv.innerHTML = "Password length must be less than 129"
                errorDiv.style.display = 'block';
            } else if (!upper && !lower) {
                errorDiv.innerHTML = "Must select a character case";
                errorDiv.style.display = 'block';
                document.getElementById('include-upper').className = 'form-check-input border-danger'
                document.getElementById('include-lower').className = 'form-check-input border-danger'
            } else {
                authRequest('/generate.php', data).then(response => {
                    if (response.status === 'success') {
                        errorDiv.style.display = 'none';
                        document.getElementById('include-upper').className = 'form-check-input'
                        document.getElementById('include-lower').className = 'form-check-input'
                        document.getElementById('generated-password').value = response.password;
                    }
                })
            }

        });
    }

    //Search for accounts
    function clickSearch(event) {

        document.body.innerHTML = "<div class='container text-center' id='search-page'><div class='row-2 p-0'><p role='button'class='ms-3 mt-3 position-absolute h5' id='back-arrow-search'><i class='fa-solid fa-arrow-left'></i> </p><p class='fontweight-bold'>Search</p></div><div class='search-container'><input id='search-box' type='text'  class='form-control  my-4 roundish-box'></input><button id='search-button' role='button' class='btn p-1 w-50' >Search</button><p id='search-error'class='m-0' style='color: red; font-size: 1rem;'></p></div></div>";
        document.getElementById('back-arrow-search').addEventListener("click", function () {
            createVault();
        });

        const searchButton = document.getElementById('search-button')
        searchButton.addEventListener('click', function (event) {
            const searchquery = document.getElementById('search-box').value;
            if (searchquery.length === 0) {
                document.getElementById('search-error').innerHTML = "Search box cannot be empty. Please enter a keyword to proceed.";
            } else {
                //creating and sending search results
                const searchTerm = document.getElementById('search-box').value;
                const idval = sessionStorage.getItem("user_id")
                const data = {id: idval, searchTerm: searchTerm};
                //Request stored account data
                authRequest("/search.php", data).then(response => {
                    let searchResults = "<div class='container text-center' id='search-results'><div class='row-2 p-0'><p role='button'class='ms-3 mt-3 position-absolute h5' id='back-arrow-search-results'><i class='fa-solid fa-arrow-left'></i> </p><p class='fontweight-bold'>Search Results</p></div><div class='search-container'>";

                    if (response.accounts.length > 0) {
                        for (let i = 0; i < response.accounts.length; i++) {
                            const accid = response.accounts[i].accid;
                            const accusername = response.accounts[i].accusername;
                            const accplatform = response.accounts[i].accplatform;
                            const accpassword = response.accounts[i].accpassword;
                            let iconpath = imgfetchUrl + response.accounts[i].iconpath; //Embed user's id on each account so createVault can always be called

                            searchResults += "<div class='btn container p-0 border-0 text-dark bg-transparent extra-space' id='account." + accid + "'><div role='button' class='row text-start p-0 m-0'><div class='col-4 h-100 d-flex justify-content-center bg-light rounded p-0' style='width:80px;'>" +
                                "<img id='accountimg." + accid + "' src='" + iconpath + "' class='rounded p-1'></div><div class='col-7 align-self-center'>" +
                                "<p id='accountplatform." + accid + "' class='text-truncate fw-bold m-0'>" + accplatform + "</p>" +
                                "<p id='accpassword." + accid + "' hidden>" + accpassword + "</p>" +
                                "<p id='accountusername." + accid + "' class='text-truncate fw-normal m-0' style='font-size: 1rem;'>" + accusername + "</p></div><div class='col-1 align-self-center text-end p-0'><p class='m-0'><i class='fa-solid fa-arrow-right'></i></p></div><div><p class = 'text-truncate fw-bold m-0'>Password:</p><input id='account-password' type='password' placeholder='password' class='w-100 form-control small-password-box' value='" + accpassword + "'/></div></div></div><hr class='mx-auto my-auto w-75 border-1'>";
                        }
                        searchResults += "</div></div>"
                        document.body.innerHTML = searchResults;
                        //Select all div ids that begin with "account." Add event listener to every account currently added
                        let accounts = document.querySelectorAll('[id^="account."]');
                        if (accounts) {
                            accounts.forEach(account => {
                                account.addEventListener('click', function () {
                                    let accid = account.id.toString();
                                    accid = accid.slice(8, accid.length);
                                    const imgpath = account.querySelector('img[id^="accountimg."]').src
                                    const accountinfo = {"accid": accid, "accimgpath": imgpath}
                                    getAccountDetails(accountinfo);
                                });
                            });
                        }
                        document.getElementById('back-arrow-search-results').addEventListener('click', clickSearch);
                    } else {
                        searchResults += "<p class='fontweight-bold'>No Results</p></div></div>"
                        document.body.innerHTML = searchResults;
                        document.getElementById('back-arrow-search-results').addEventListener('click', clickSearch);
                    }

                });
            }
        });

    }

    //Check Invites
    function clickInvites(event) {

            const idval = sessionStorage.getItem("user_id")
            const data = {id: idval};
            //Request stored account data
            authRequest("/invites.php", data).then(response => {
                let passwordInvites = `
                <div class='container py-3' id='invite-page'>
                    <div class='mb-4 d-flex align-items-center'>
                        <p role='button' class='me-3 mb-0 h5' id='back-arrow-invites'>
                            <i class='fa-solid fa-arrow-left'></i>
                        </p>
                        <p class='mb-0 h5 fw-bold'>Password Invites</p>
                    </div>
                    <div class='invite-container'>
            `;

                if (response.invites.length > 0) {
                    for (let i = 0; i < response.invites.length; i++) {
                        const accid = response.invites[i].accid;
                        const accusername = response.invites[i].accusername;
                        const sender = response.invites[i].sender;
                        const accplatform= response.invites[i].accplatform;
                        let iconpath = imgfetchUrl + response.invites[i].iconpath; //Embed user's id on each account so createVault can always be called
                        passwordInvites += `
                            <div class='card p-3 shadow-sm mb-3' id='account.${accid}'>
                                <div class='row g-0 align-items-center'>
                                    <div class='col-auto'>
                                        <img id='accountimg.${accid}' src='${iconpath}' alt='${accplatform}' class='img-fluid rounded' style='max-width: 60px;'>
                                    </div>
                                    <div class='col ms-3'>
                                        <p id='accountplatform.${accid}' class='fw-bold mb-1'>${accplatform}</p>
                                        <p id='accountusername.${accid}' class='text-muted mb-0'>${accusername}</p>
                                    </div>
                                </div>
                                <div class='row mt-3'>
                                    <div class='col-6'>
                                        <button type='button' class='btn btn-success w-100 accept-invite' data-accid='${accid}' data-sender='${sender}'>Accept</button>
                                    </div>
                                    <div class='col-6'>
                                        <button type='button' class='btn btn-outline-danger w-100 deny-invite' data-accid='${accid}' data-sender='${sender}' data-iconpath='${iconpath}'>Deny</button>
                                    </div>
                                </div>
                                <p class='text-center text-secondary mt-2 mb-0'>Sent by: ${sender}</p>
                            </div>
                        `;
                    }
                    passwordInvites += "</div></div>";
                    document.body.innerHTML = passwordInvites;


                    //Deny invites for each box
                    document.querySelectorAll('.deny-invite').forEach(button => {
                        button.addEventListener('click', function (e) {
                            e.stopPropagation(); // Prevent parent click event

                            const accid = this.getAttribute('data-accid');
                            const sender = this.getAttribute('data-sender');
                            const id = sessionStorage.getItem("user_id");

                            const data = {
                                id: id,
                                accid: accid,
                            };

                            authRequest('/deny_invite.php', data).then(response => {
                                if (response.status === 'success') {
                                    clickInvites(); // Refresh UI
                                } else {
                                    alert('Failed to deny invite: ' + result.message);
                                }
                            })
                            .catch(err => console.error('Error:', err));
                        });
                    });

                    //accepting invites for each box
                    document.querySelectorAll('.accept-invite').forEach(button => {
                        button.addEventListener('click', function (e) {
                            e.stopPropagation(); // Prevent parent click

                            const accid = this.getAttribute('data-accid');
                            const id = sessionStorage.getItem("user_id");

                            const card = this.closest('[id^="account."]');
                            const img = card.querySelector('img[id^="accountimg."]');
                            const iconpath = img ? img.src : ''; // fallback to empty if not found

                            const data = {
                                id: id,
                                accid: accid
                            };

                            const accountinfo = {"accid": accid, "accimgpath": iconpath}

                            authRequest('/accept_invite.php', data).then(response => {

                                if (response.status === 'success') {
                                    getAccountDetails(accountinfo);
                                    //clickInvites(); // Refresh UI
                                } else {
                                    alert('Failed to accept invite: ' + result.message);
                                }
                            })
                            .catch(err => console.error('Error:', err));
                        });
                    });




                    //Select all div ids that begin with "account." Add event listener to every account currently added
                    let accounts = document.querySelectorAll('[id^="account."]');
                    if (accounts) {
                        accounts.forEach(account => {
                            account.addEventListener('click', function () {
                                let accid = account.id.toString();
                                accid = accid.slice(8, accid.length);
                                const imgpath = account.querySelector('img[id^="accountimg."]').src
                                const accountinfo = {"accid": accid, "accimgpath": imgpath}
                                getAccountDetails(accountinfo);
                            });
                        });
                    }
                    document.getElementById('back-arrow-invites').addEventListener("click", function () {
                        createVault();
                    });
                } else {
                    passwordInvites += "<p class='fontweight-bold'>--No Pending Invites--</p></div></div>";
                    passwordInvites += "</div></div>";
                    document.body.innerHTML = passwordInvites;
                    document.getElementById('back-arrow-invites').addEventListener("click", function () {
                        createVault();
                    });
                }

            });



        /*
        <button type='button' class='mt-2 btn w-100' id='accept-invite'>Accept</button>
        <button type='button' class='mt-2 btn w-100' id='deny-invite'>Deny</button>
        <p id='invite-sender' class='m-0' style='color: grey; font-size: 1rem;'> Sent by: Person1</p>
        */
        // "<p class='fontweight-bold'>--No Invites--</p></div></div>";

    }

    //get details for a selected account on the vault page
    //accinfo is {'accid':accid,'imgpath':imgpath}
    function getAccountDetails(accountinfo) {
        // Prepare the data for the request
        const data = {
            accid: accountinfo['accid'],
            id: sessionStorage.getItem("user_id")
        };

        // Use the authRequest function to make the API call and get fresh data
        authRequest('/view_account_details.php', data).then(response => {
            if (response.status === 'success') {
                const accinfo = {
                    "accid": response.account.accid,
                    "accusername": response.account.accusername,
                    "accplatform": response.account.accplatform,
                    "accimgpath": accountinfo['accimgpath'],
                    "accpassword": response.account.accpassword,
                    "owner": response.account.owner, //Boolean to represent if you are/are not the owner
                    "sharing": response.sharing,
                };
                viewAccountDetails(accinfo);
            } else {
                console.error('Error:', response ? response.message : 'No response received');
            }
        }).catch(error => {
            console.error('Request error:', error);
        });
    }

    function generateInviteEntry(username, status, owner){
        const inviteEntry = document.createElement('div');
        inviteEntry.className = 'd-flex justify-content-between align-items-center pb-2';
        inviteEntry.style.fontSize = "1.15rem";

        //No icon if accepted- status of 1. status of 2 (denied) shouldn't be sent to this function
        //If an owner entry is being generated, icon should be a crown
        let iconHTML = '';
        if (status === 0) {
            iconHTML = 'fa-regular fa-clock ms-2'
        } else if (owner === true) {
            iconHTML = 'fa-solid fa-crown ms-2'
        }

        const hue = Math.random() * 360; const randomColor = `hsl(${hue}, 100%, 30%)`;
        inviteEntry.innerHTML = "<div class='fw-bold text-white border rounded-circle' style='background-color: "+randomColor+"; padding-top: 6px; min-width: 40px; min-height: 40px;'>"+username[0].toUpperCase()+"</div><div class='ms-2 text-truncate'>"+username+"</div><i class='"+iconHTML+" ms-auto'></i></div>";
        return inviteEntry;
    }

    //Renders an account's details
    function viewAccountDetails(accountDetails) {
        const timestamp = new Date().getTime();//Needed to resolve caching issues when updating account images
        //HTML for successful account editing modal, inserted after innerHTML
        const editSuccessModalHTML = "<div class='modal hidden' id='editSuccessModal'><div class='modal-container'><div class='row mb-2'><div class='col-12 text-start'><button type='button' class='btn-close' id='edit-popup-close' style='font-size: 0.75rem'></button></div></div><div class='row mb-2'><div class='col-12 fw-bold text-center'>Account information updated successfully!</div></div></div></div>";

        document.body.innerHTML = "<div id='account-page." + accountDetails['accid'] + "'><div class='container text-center py-0 m-0'><div class='row align-items-center'><div class='col-2 p-0 text-start'><p role='button' class='ms-3 mt-3' id='back-arrow-account'><i class='fa-solid fa-arrow-left'></i></p></div><div class='col-6' p-0'></div><div class='col-2 p-0 text-end'><i id='delete-icon' role='button' class='btn p-2 fa fa-trash' style='font-size: 1rem; width: 38px; height: 38px;'></i></div><div class='col-2 p-0'><i id='edit-icon' role='button' class='btn p-2 fa fa-pencil'></i></div>" +
            "</div><div class='container p-0'><div class='container p-0'><div class='row text-start p-0 m-0'><div class='col-4 border border-dark h-100 d-flex justify-content-center bg-light rounded p-0' style='width:80px;'>" +
            "<img id='acc-img' src='" + accountDetails['accimgpath'] + "?ts=" + timestamp + "' class='rounded p-1'></div><div class='col-8 align-self-center pe-0'>" +
            "<h4 id='accplatform' class='text-truncate fw-bold m-0' data-bs-toggle='tooltip' title='"+accountDetails['accplatform']+"'>" + accountDetails['accplatform'] + "</h4>" +
            "<p id='account-username' class='text-truncate fw-normal m-0' style='font-size: 1rem;' data-bs-toggle='tooltip' title='"+accountDetails['accusername']+"'>" + accountDetails['accusername'] + "</p></div></div></div><hr><div class='text-start p-0 m-0'><p class='mb-1' style='font-size:1.05rem;'>Password:</p><div class='row'><div class='col-10'>" +
            "<input id='account-password' type='password' placeholder='password' class='w-100 form-control rounded' value='" + accountDetails['accpassword'] + "'></div><div class='col-2 ps-0 py-0'><div role='button' class='btn p-1' style='width: 39px; font-size: 1rem;' id='eye-icon2'><i class='fa-regular fa-eye'></i></div></div></div></div><hr class='mx-auto w-75'></div>" +
            "<!--Pop up for confirm delete password-->" +
            "<div class='modal hidden' id='deleteModal'><div class='modal-container'><div class='row mb-2 '><div class='col-9 fw-bold'>Delete password account?</div><div class='col-3'><button type='button' class='btn-close' id='delete-popup-close'></button></div></div><hr class='m-0'><div class='button-container'><button type='button' class='mt-2 btn w-100' id='delete-Yes'>Yes</button><button type='button' class='mt-2 btn w-100' id='delete-No'>No</button></div><p id='account-error' class='m-0' style='color: red; font-size: 1rem;'></p></div></div>" +
            "<p class='mb-1 text-start' style='font-size:1.05rem;'>Password Shared With:</p><div id='pass-share-container' class='password-share-container position-relative p-3 w-100' style='height: 220px;'>" +
            //This shares-container holds the "No One" text or a list of invited users.
            "<div id='shares-container' class='w-100 p-0' style='height: 150px; overflow-y: auto;'></div>" +
            //This is the actual sharing feature (+ Share button and username input textbox)
            "<div class='d-flex w-100 align-items-center position-absolute bottom-0 end-0 px-3 pb-3'><div class='w-100' id='share-message' style='display: none;'></div><div id='share-col' style='display: block;' class='p-0 me-2'><div id='share-button' role='button' class='btn py-1'>+Share</div></div><div id='text-col' style='display: block;' class='flex-grow-1 p-0'><input id='username-share' maxlength='25' type='text' placeholder='Username' class='form-control rounded'></div></div></div></div></div>";


            //Populating the shares container with "No One" or a list of invited users
            let sharesContainer = document.getElementById('shares-container');
            //If no shares have been made, only the owner is listed in the sharing data and is viewing the account
            if(accountDetails["sharing"].length === 1){
                sharesContainer.innerHTML="<div id='no-one' style='font-size: 1.15rem;'>-- No One! --</div>"
            } else {
                for (let i = 0; i < accountDetails["sharing"].length; i++) {
                    let entry = accountDetails["sharing"][i];

                    if (entry["status"] === 2) continue; // Skip denied

                    if (accountDetails["owner"] === true) {
                        // Don't show yourself in your own list
                        if (entry["owner"] === false) {
                            sharesContainer.appendChild(generateInviteEntry(entry["username"], entry["status"], false));
                        }
                    } else {
                        // You’re not the owner, so include everyone else
                        // Give the crown to the one who IS the owner
                        const isOwner = entry["owner"] === true;
                        sharesContainer.appendChild(generateInviteEntry(entry["username"], entry["status"], isOwner));
                    }
                }
            }

        document.getElementById("eye-icon2").addEventListener("click", function () {
            const accPasstext = document.getElementById('account-password');
            if (accPasstext.type === 'text') {
                accPasstext.type = 'password';
            } else {
                accPasstext.type = 'text';
            }
        });

        document.getElementById("back-arrow-account").addEventListener("click", function () {
                createVault();
        });

        //------------------------------------- Editing Account Stuff -------------------------------------------- //
        document.body.insertAdjacentHTML('beforeend', editSuccessModalHTML);
        //This is for the X button on the edit account modal
        document.getElementById("edit-popup-close").addEventListener("click", function () {
            document.getElementById("editSuccessModal").classList.add("hidden");
        });
        document.getElementById('edit-icon').addEventListener('click', function () {
            editAccountDetails(accountDetails);
        });

        //-------------------------------------- Sending Shares ------------------------------------------//
        document.getElementById('share-button').addEventListener('click', function () {
            let usernameToInvite = document.getElementById("username-share").value;
            const sharecol = document.getElementById('share-col');
            const textcol = document.getElementById('text-col');
            let shareMessage = document.getElementById('share-message');
            textcol.style.display = 'none';
            sharecol.style.display = 'none';
            shareMessage.style.display = 'block';

            //Frontend only html escaping. STILL enforced on the backend so hah
            const escapeHtml = unsafe => {
                return unsafe
                    .replaceAll("&", "&amp;")
                    .replaceAll("<", "&lt;")
                    .replaceAll(">", "&gt;")
                    .replaceAll('"', "&quot;")
                    .replaceAll("'", "&#039;");
            };

            //Frontend error check
            if (usernameToInvite.length <= 0) {
                shareMessage.innerHTML = "<div class='text-danger'>Must Provide a Username</div>";
                setTimeout(function () {
                    shareMessage.style.display = 'none';
                    sharecol.style.display = 'block';
                    textcol.style.display = 'block';
                    shareMessage.innerHTML = '';
                }, 2000);
            } else if (usernameToInvite.length > 25) {
                shareMessage.innerHTML = "<div class='text-danger'>Provided Username is Too Long</div>";
                setTimeout(function () {
                    shareMessage.style.display = 'none';
                    sharecol.style.display = 'block';
                    textcol.style.display = 'block';
                    shareMessage.innerHTML = '';
                }, 2000);
            }  else {

                //Make a POST request to the invite backend
                const data = {"username": usernameToInvite, "sender_id": sessionStorage.getItem("user_id"), "accid": accountDetails["accid"]}
                usernameToInvite = escapeHtml(usernameToInvite);
                authRequest("/share_account.php",data).then(response => {
                    if (response.status.toString() === "success") {
                        shareMessage.innerHTML = "<div class='text-secondary'>" + usernameToInvite + " was Successfully Invited</div>";
                        setTimeout(function () {
                            shareMessage.style.display = 'none';
                            sharecol.style.display = 'block';
                            textcol.style.display = 'block';
                            shareMessage.innerHTML = '';
                            const noneElement = document.getElementById('no-one');
                            if (noneElement) {
                                sharesContainer.removeChild(noneElement);
                            }
                            //HTML for listing invited users- not currently dynamic (clock must be updated)
                            //When linking is done, list entires in the shared with container using this
                            const entry = generateInviteEntry(usernameToInvite, 0, false);
                            sharesContainer.appendChild(entry);
                        }, 3000);

                    } else {
                        if(response.message === "Target user not found.") {
                            shareMessage.innerHTML = "<div class='text-danger'>"+usernameToInvite+" Does Not Exist- User Not Invited</div>";
                            setTimeout(function () {
                                shareMessage.style.display = 'none';
                                sharecol.style.display = 'block';
                                textcol.style.display = 'block';
                                shareMessage.innerHTML = '';
                            }, 2000);
                        }
                        else if(response.message === "Account already shared or invite already sent."){
                            shareMessage.innerHTML = "<div class='text-danger'>"+usernameToInvite+" Has Already Been Invited</div>";
                            setTimeout(function () {
                                shareMessage.style.display = 'none';
                                sharecol.style.display = 'block';
                                textcol.style.display = 'block';
                                shareMessage.innerHTML = '';
                            }, 2000);
                        }
                        if(response.message === "Cannot share account with self."){
                            shareMessage.innerHTML = "<div class='text-danger'>Cannot Invite Yourself</div>";
                            setTimeout(function () {
                                shareMessage.style.display = 'none';
                                sharecol.style.display = 'block';
                                textcol.style.display = 'block';
                                shareMessage.innerHTML = '';
                            }, 2000);
                        }
                        else if(response.message === "Missing required fields."){
                            shareMessage.innerHTML = "<div class='text-danger'>Missing Required Fields</div>";
                            setTimeout(function () {
                                shareMessage.style.display = 'none';
                                sharecol.style.display = 'block';
                                textcol.style.display = 'block';
                                shareMessage.innerHTML = '';
                            }, 2000);
                        }
                    }
                })
                .catch((error) => {
                    console.error('Error:', error);
                });
            }
        });

        //-------------------------------------- Deleting ------------------------------------------//
        const deletePopUp = document.getElementById("deleteModal");
        const deltePopUpExit = document.getElementById("delete-popup-close");
        document.getElementById("delete-icon").addEventListener("click", function () {
            // console.log('delete button is clicked');
            deletePopUp.className = "modal";
            if (deletePopUp.className === "modal") {
                //console.log('it should be showuing the pop up');
            }
        })

        //Close the delete modal if its open
        if (deltePopUpExit) {
            deltePopUpExit.addEventListener('click', function () {
                deletePopUp.className = "modal hidden";
            });
        }
        //remove pop up if "no" is clicked
        document.getElementById("delete-No").addEventListener("click", function () {
            deletePopUp.className = "modal hidden";
        })

        //Request deleting
        const deleteButton = document.getElementById('delete-Yes')
        deleteButton.addEventListener('click', function (event) {
            const idval = sessionStorage.getItem("user_id")
            const accid1 = accountDetails['accid'];//accid stored in AccountDetails
            const data = {
                id: idval,
                accid: accid1
            };
            authRequest('/delete_account.php', data)  // Capture the HTTP response
                .then(response => {
                    if (response.status.toString() !== "failure") {
                        createVault();
                    } else {
                        //console.log("yes was clicked error");
                        document.getElementById('account-error').innerHTML = `Error: ${response.errors.toString()}`;
                    }
                })
                .catch((error) => {
                    console.error('Error:', error);
                    //document.getElementById('error').innerHTML = `Error: ${error.message}`;
                });
        });


        //if user is not owner remove edit and delete icons *-Temp solution probably-*
        if(accountDetails.owner !== true){
            const deleteIcon = document.getElementById('delete-icon');
            const editIcon = document.getElementById('edit-icon');

            if (deleteIcon) deleteIcon.remove();
            if (editIcon) editIcon.remove();
        }


    }

    function editAccountDetails(accountDetails) {
        const timestamp = new Date().getTime();//Needed to resolve caching issues when updating account images

        document.body.innerHTML = "<div id='password-generator-container'></div><div class='container text-center py-0 m-0' id='edit-page'> <div class='container p-3 pb-2'> <div class='row d-flex align-items-center justify-content-end'> <div class='col-3 py-0' style='font-size: 1.15rem;'> <div id='cancel-button' role='button' class='p-0'>Cancel</div> </div> <div class='col-3 p-0'> <div id='save-edits' role='button' class='btn w-100 p-1'>Save</div> </div> </div> </div> <div class='container p-0'> <form enctype='multipart/form-data' class='w-100'> <div class='row d-flex align-content-center'> <div class='col-4 pe-0 align-content-center'> <div role='button' class='bg-light rounded border border-dark' style='height: 99px;'> <label for='edit-icon' class='h-100 w-100 align-content-center' style='cursor: pointer;'>" +
            "<p id='edit-img-loc' class='m-0'>" +
            "<img src='" + accountDetails["accimgpath"] + "?ts=" + timestamp + "'></p><input id='edit-icon' type='file' accept='.jpg, .png, .jpeg' style='display: none;'></label></div></div></div><div class='text-start p-0 m-0 mt-1'><p class='mb-0' style='font-size: 1rem;'>Website Name:</p></div>" +
            "<label for='edit-platform' class='w-100'><input id='edit-platform' value='" + accountDetails["accplatform"] + "' type='text' placeholder='Website Name' maxlength='25' class='w-100 form-control rounded'> </label><div class='text-start p-0 m-0'><p class='mb-0' style='font-size: 1rem;'>Username: </p><label for='edit-username' class='w-100'>" +
            "<input id='edit-username'  value='" + accountDetails["accusername"] + "' type='text' placeholder='Username/email' maxlength='25' class='w-100 form-control rounded'> </label></div><hr class='mt-2 mb-1'><div class='text-start p-0 m-0'> <p class='mb-0' style='font-size: 1rem;'>Password: </p> <div class='row'> <div class='col-8 pe-0'> <label for='edit-password' class='w-100'>" +
            "<input id='edit-password'  value='" + accountDetails["accpassword"] + "' type='password' placeholder='Password' maxlength='128' class='w-100 form-control rounded'> </label>" +
            "</div><div class='col-2 pe-0 ps-2 m-0 py-0'><div role='button' class='btn p-0 h-100' style='width: 39px; font-size: 1rem;' id='edit-reveal'><i class='fa-regular fa-eye p-2'></i></div></div><div class='col-2 ps-0 py-0'> <div role='button' class='btn p-0 h-100' style='width: 39px; font-size: 1rem;' id='edit-password-icon'> <i class='fa-solid fa-pencil p-2'></i> </div> </div> </div> </div> </form> </div> </div>" +
            "<p id='edit-error' class='text-danger text-center mb-2' style='font-size: 0.9rem;'></p> <!-- Error field --> <hr class='mt-2 mb-1'>"

        let editpass = document.getElementById('edit-password');
        const uploadEditImage = document.getElementById("edit-icon");
        const editimgLoc = document.getElementById('edit-img-loc');
        const cancel = document.getElementById('cancel-button');
        const save = document.getElementById('save-edits');
        const errorMsg = document.getElementById('edit-error');

        document.getElementById('edit-reveal').addEventListener('click', function () {
            if (editpass.type === 'password') {
                editpass.type = 'text';
            } else {
                editpass.type = 'password';
            }
        });

        document.getElementById('edit-password-icon').addEventListener('click', function () {
            loadPasswordGenerator();
            document.getElementById('password-generator-container').firstChild.style.bottom = '15px';
            document.getElementById('password-generator-container').firstChild.style.top = '';
        })
        //Render image to USER to confirm they've chosen the correct img
        let editfiledata = "";
        if (uploadEditImage) {
            uploadEditImage.addEventListener('change', function () {
                if (this.files && this.files[0]) {
                    editfiledata = this.files[0];
                    var reader = new FileReader();
                    reader.onload = function (e) {
                        editimgLoc.innerHTML = "<img src='" + e.target.result + "'>"
                    };
                    reader.readAsDataURL(this.files[0]);
                }
            });
        }
        cancel.addEventListener('click', function () {
            //Nothing changed so should be fine to leave as is
            viewAccountDetails(accountDetails);
        });

        save.addEventListener('click', async function () {

            //Adding checks for valid file
            const file = uploadEditImage.files[0];
            let uploadSuccess = false; //Used for correct response to user clicking save
            let newFilePath = ""; // Used to send newFilePath to viewAccountDetails to properly render later
            if (file) {

                //List of acceptable image formats
                const validTypes = ['image/jpeg', 'image/png'];

                //checks for valid image file format
                if (!validTypes.includes(file.type)) {
                    errorMsg.innerHTML = "Invalid file type. Please select a JPG or PNG image.";
                    this.value = ''; // reset the input
                    setTimeout(() => {
                        errorMsg.innerHTML = "";
                    }, 3000);
                    return;
                }

                //Checking for File size ( 4MB Limit currently )
                if (file.size > 4 * 1024 * 1024) {
                    errorMsg.innerHTML = "Image must be smaller than 4MB.";
                    uploadEditImage.value = '';
                    setTimeout(() => {
                        errorMsg.innerHTML = "";
                    }, 3000);
                    return;
                }


                //Preparing post request payload
                const userInfo = {
                    id: sessionStorage.getItem("user_id"),
                    accid: accountDetails["accid"]
                };


                try {
                    const response = await authFileRequest("/edit_image.php", userInfo, file);
                    if (response.status === "success") {
                        uploadSuccess = true;
                        newFilePath = response.account.iconpath;
                    } else {
                        errorMsg.innerHTML = response.message = "Error updating account image.";
                        setTimeout(() => errorMsg.innerHTML = "", 3000);
                        return;
                    }
                } catch (error) {
                    console.error("Image Upload Error:", error);
                    errorMsg.innerHTML = "An error occurred while updating the account image.";
                    setTimeout(() => errorMsg.innerHTML = "", 3000);
                    return;
                }
            }


            //Preparing payload for account information
            const updatedData = {
                id: sessionStorage.getItem("user_id"),
                accid: accountDetails["accid"],
                accplatform: document.getElementById('edit-platform').value,
                accusername: document.getElementById('edit-username').value,
                accpassword: document.getElementById('edit-password').value
            };


            let updateInfromation = false;//bool to check for user edited information
            let accountInfo = accountDetails;//store orig. account details in case user does not edit their details but changes image
            try {
                const response = await authRequest("/edit_account.php", updatedData);
                if (response.status === "success") {
                    updateInfromation = true;
                    //Fixing response to  match structure of ViewAccountDetails
                    response.account.accimgpath = response.account.iconpath;
                    delete response.account.iconpath;

                    if (!uploadSuccess) {
                        response.account.accimgpath = imgfetchUrl + response.account.accimgpath;
                    } else {
                        response.account.accimgpath = imgfetchUrl + newFilePath + "?ts=" + timestamp;
                    }
                    //store updated account information on success
                    accountInfo = response.account;
                }
            } catch (error) {
                console.error("Update Error:", error);
                errorMsg.innerHTML = "An error occurred while updating the account.";
                setTimeout(() => errorMsg.innerHTML = "", 3000);
                return;
            }

            function updateAndShowSuccess(response) {
                return new Promise((resolve) => {
                    //console.log("Response: ",response);
                    response["sharing"] = accountDetails["sharing"];
                    response["owner"] = accountDetails["owner"];
                    //console.log("New Response: ",response);
                    viewAccountDetails(response);
                    setTimeout(() => {
                        resolve(); // Resolve the promise after DOM updates
                    }); // Small delay to ensure the DOM is updated
                });
            }

            //show an error if neither info or image was updated
            if (!uploadSuccess && !updateInfromation) {
                errorMsg.innerHTML = "Error updating account.";
                setTimeout(() => errorMsg.innerHTML = "", 3000);
                return;
            } else if (uploadSuccess && updateInfromation) {
                updateAndShowSuccess(accountInfo).then(() => {
                    const modal = document.getElementById("editSuccessModal");
                    if (modal) {
                        modal.classList.remove("hidden");
                    }
                });
            } else if (uploadSuccess && !updateInfromation) {
                accountInfo.accimgpath = imgfetchUrl + newFilePath + "?ts=" + timestamp;

                updateAndShowSuccess(accountInfo).then(() => {
                    const modal = document.getElementById("editSuccessModal");
                    if (modal) {
                        modal.classList.remove("hidden");
                    }
                });
            } else if (!uploadSuccess && updateInfromation) {
                updateAndShowSuccess(accountInfo).then(() => {
                    const modal = document.getElementById("editSuccessModal");
                    if (modal) {
                        modal.classList.remove("hidden");
                    }
                });
            }

        })
    }

    //Create Vault page using user's ID and username
    function createVault() {
        const timestamp = new Date().getTime(); //Needed for resolving caching issues when editing account images
        const userval = sessionStorage.getItem("username");
        const idval = sessionStorage.getItem("user_id");
        const data = {id: idval};
        //Request stored account data
        authRequest("/vault.php", data).then(response => {
            let accinfostr = "<div id='vault-page'><div class='container py-0 my-0 text-center overflow-auto' style='max-height: 486px;'><div class='text-end mt-3 top-0 end-0 h5'><i id='search' role='button' class='fa-solid fa-magnifying-glass me-3' style='font-size: 1rem;'></i><span role  = 'button' class = 'position-relative d-inline-block'><i id='invites'class='fa-solid fa-envelope'></i><span id='notification-dot'class='notification_badge'> </span></span></div><p class='fw-bold mb-4'>" + userval + "'s Password Vault</p><hr><div id='account-list' class='d-grid gap-3'>";
            for (let i = 0; i < response.accounts.length; i++) {
                const accid = response.accounts[i].accid;
                const accusername = response.accounts[i].accusername;
                const accplatform = response.accounts[i].accplatform;
                const accpassword = response.accounts[i].accpassword;
                let iconpath = imgfetchUrl + response.accounts[i].iconpath + "?ts=" + timestamp; //Embed user's id on each account so createVault can always be called
                                                                                                 //Include Timestamp to avoid caching issues when editing account images
                accinfostr += "<div class='btn container p-0 border-0 text-dark bg-transparent' id='account." + accid + "'><div role='button' class='row text-start p-0 m-0'><div class='col-4 h-100 d-flex justify-content-center bg-light rounded p-0' style='width:80px;'>" +
                    "<img id='accountimg." + accid + "' src='" + iconpath + "' class='rounded p-1'></div><div class='col-7 align-self-center'>" +
                    "<p id='accountplatform." + accid + "' class='text-truncate fw-bold m-0'>" + accplatform + "</p>" +
                    "<p id='accpassword." + accid + "' hidden>" + accpassword + "</p>" +
                    "<p id='accountusername." + accid + "' class='text-truncate fw-normal m-0' style='font-size: 1rem;'>" + accusername + "</p></div><div class='col-1 align-self-center text-end p-0'><p class='m-0'><i class='fa-solid fa-arrow-right'></i></p></div></div></div><hr class='mx-auto my-auto w-75'>";
            }
            accinfostr += "</div></div><div class='container m-0 p-0 fixed-bottom' style='background-color: #B36591;'><div class='row align-items-center'><div class='btn col-4 py-3 border-0 rounded-0'><i id='add-button' role='button' class='text-dark fa-solid fa-plus' style='font-size: 1.75rem;'></i></div><div class='btn col-4 py-3 border-0 rounded-0'><i id='strength-button' role='button' class='text-dark fa-solid fa-dumbbell' style='font-size: 1.75rem;'></i></div><div class='btn col-4 py-3 border-0 rounded-0 ps-0'><i id='generate-button' role='button' class='text-dark fa-solid fa-arrows-spin' style='font-size: 1.75rem;'></i></div></div></div></div>";
            document.body.innerHTML = accinfostr;

            document.getElementById('add-button').addEventListener('click', clickAdd);
            document.getElementById('strength-button').addEventListener('click', clickStrength);
            document.getElementById('generate-button').addEventListener('click', clickGenerate);
            document.getElementById('invites').addEventListener('click', clickInvites);
            document.getElementById('search').addEventListener('click', clickSearch);

            //Select all div ids that begin with "account." Add event listener to every account currently added
            let accounts = document.querySelectorAll('[id^="account."]');
            if (accounts) {
                accounts.forEach(account => {
                    account.addEventListener('click', function () {
                        let accid = account.id.toString();
                        accid = accid.slice(8, accid.length);
                        const imgpath = account.querySelector('img[id^="accountimg."]').src
                        const accountinfo = {"accid": accid, "accimgpath": imgpath}
                        getAccountDetails(accountinfo);
                    });
                });
            }

        });

    }

    //------------------------------------------------------------------------------------------------//
    function loadPasswordGenerator() {
        const container = document.getElementById('password-generator-container');
        if (!container) return;

        container.innerHTML = `<div class="rounded p-3 text-start" style="background-color: white; max-width: 320px; min-width: 320px; position: absolute; top: 300px; right: 15px"><div class="d-flex justify-content-between align-items-center mb-2">
                <label for="password-length" >Maximum Password Length:</label><input type="text" id="password-length" class="form-control rounded text-center" value="10" style=" border-width: 2px; width: 60px; text-align: center;"></div><p id="password-error" class="text-danger text-center mb-2" font-size: 0.9rem;"></p><div class="d-flex justify-content-between align-items-center mb-2"><label for="use-special-chars" >Use Special Characters:</label><input type="checkbox" id="use-special-chars" class="form-check-input" style = "border-width: 2px;"></div><div class="d-flex justify-content-between align-items-center"><button id="generate-password" class="btn p-0 ms-0" style="font-size: 1.1rem; min-width: 80px; margin-right: 10px"">Generate</button>
                <input type="text" id="generated-password" class="form-control rounded" 
                    placeholder="Password" readonly 
                    style="background-color: white; text-align: left; border-width: 2px;">
            </div></div>`;

        // event listener for the generate button
        document.getElementById('generate-password').addEventListener('click', function () {
            const length = parseInt(document.getElementById('password-length').value, 10);
            const useSpecialChars = document.getElementById('use-special-chars').checked;
            const errorMsg = document.getElementById('password-error');

            if (isNaN(length) || length < 1) {
                document.getElementById('password-error').innerHTML = "Password length must be at least 1!";
                setTimeout(function () { //Error appears for 3 seconds so that the edit page isn't impacted too much by the error
                    document.getElementById('password-error').innerHTML = "";
                }, 3000);
                return;
            } else if (length > 128) {
                document.getElementById('password-error').innerHTML = "Password length must be 128 or lower!";
                setTimeout(function () {
                    document.getElementById('password-error').innerHTML = "";
                }, 3000);
                return;
            } else {
                document.getElementById('password-error').innerHTML = "";
            }


            const data = {
                id: sessionStorage.getItem("user_id"),
                max: length,
                Special: useSpecialChars
            };

            authRequest("/module_generate.php", data)  // Send request
                .then(response => {
                    if (response.status.toString() !== "failure") {
                        document.getElementById('generated-password').value = response.password; // Update password field
                    } else {
                        errorMsg.innerHTML = response.message || "Error generating password.";
                        errorMsg.style.visibility = "visible";
                    }
                })
                .catch((error) => {
                    console.error("Error:", error);
                    errorMsg.innerHTML = "An error occurred while generating the password.";
                    errorMsg.style.visibility = "visible";
                });
        });

    }
});