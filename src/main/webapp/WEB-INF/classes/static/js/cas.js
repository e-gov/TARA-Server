function APP() {
    this.errors = {
        id: {
            message: ''
        }
    },
    this.isNumber = function(event) {
        return !isNaN(parseInt(String.fromCharCode(event.which)));
    },
    this.isPhoneNumber = function(event, value) {
        if (value.length == 1) {
            return event.which == 171 || APP.isNumber(event)
        } else if (value.length > 1 && value[0] == "+") {
            return value.match(/\+/gi).length < 2 && (event.which == 171 || APP.isNumber(event));
        }
        return APP.isNumber(event);
    },
    this.isValid = function(event, f, arg1) {
        return $.inArray(event.which, [8, 13]) == 0 || f(event, arg1);
    },
    this.loginByIDCard = function() {
        this.handleIDCardCertificateResponse(API.prepareIDCardCertificate());
    },
    this.submitIDCardForm = function() {
        $("#idCardForm").submit();
    }
    this.handleIDCardCertificateResponse = function (promise) {
        var _this = this;
        promise
            .then(function(response) {
                if (response.data.ok) {
                    _this.submitIDCardForm();
                } else {
                    _this.handleError({}, 'id');
                }
            })
            .catch(function(error) {
                _this.handleError(error, 'id');
            });
    },
    this.handleError = function (error, scenario) {
        if (error.response) {
            // The request was made and the server responded with a status code
            // that falls out of the range of 2xx
            console.log(error.response.data);
            console.log(error.response.status);
            console.log(error.response.headers);
        } else if (error.request) {
            // The request was made but no response was received
            // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
            // http.ClientRequest in node.js
            console.log(error.request);
        } else {
            // Something happened in setting up the request that triggered an Error
            console.log('Error', error.message);
        }
        console.log(error.config);
        alert(this.errors[scenario]['message']);
    }
}

function API(url) {
    this.client = axios.create({
            baseURL: url,
            timeout: 60000,
            headers: {
                'Accept': 'application/json;charset=UTF-8',
            }
    }),
    this.prepareIDCardCertificate = function () {
        return this.client.get('/idcard');
    }
}