$("input[id*='personalCode']").keypress(function (event) {
    return APP.isValid(event, isNumber);
});

$("input[id*='mobileNumber']").keyup(function (event) {
    if (!isValid(event, APP.isPhoneNumber, this.value)) {
        if (this.value[0] == "+") {
            this.value = "+" + this.value.replace(/\D/g, '');
        } else {
            this.value = this.value.replace(/\D/g, '');
        }
    }
    return true;
});