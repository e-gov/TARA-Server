$("input[id*='personalCode']").keypress(function (event) {
    return APP.isValid(event, APP.isNumber);
});

$("input[id*='mobileNumber']").keyup(function (event) {
    if (!APP.isValid(event, APP.isPhoneNumber, this.value)) {
        if (this.value[0] == "+") {
            this.value = "+" + this.value.replace(/\D/g, '');
        } else {
            this.value = this.value.replace(/\D/g, '');
        }
    }
    return true;
});

$('#accordion').on('hidden.bs.collapse', APP.toggleChevron);
$('#accordion').on('shown.bs.collapse', APP.toggleChevron);