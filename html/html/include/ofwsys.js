
// select
function removeOptions(field) {
    var removedOptions = document.createElement("select"),
        i,
        j = 0;

    for (i = 0; i < field.options.length; i++) {
        if (field.options[i].selected) {
            removedOptions.options[j] = new Option();
            removedOptions.options[j].text = field.options[i].text;
            removedOptions.options[j].value = field.options[i].value;
            removedOptions.options[j].selected = true;

            field.options[i] = null;
            i--;
            j++;
        }
    }

    return removedOptions;
}

function moveOptionField(fromField, toField) {
    var insertIndex = toField.options.length,
        selectedOptions,
        insertNumber = 0,
        i;

    // find insertion point in destination field
    for (i = 0; i < toField.options.length; i++) {
        if (toField.options[i].selected) {
            insertIndex = i + 1;
            toField.options[i].selected = false;
        }
    }

    // remove options from fromField
    selectedOptions = removeOptions(fromField);

    // add empty options by increasing length
    toField.options.length += selectedOptions.options.length;

    // shift old entries down
    for (i = (toField.options.length - 1); i >= (insertIndex + selectedOptions.options.length); i--) {
        toField.options[i].text = toField.options[i - selectedOptions.options.length].text;
        toField.options[i].value = toField.options[i - selectedOptions.options.length].value;
    }

    // insert new entries
    for (i = 0; i < selectedOptions.options.length; i++, insertIndex++) {
        toField.options[insertIndex].text = selectedOptions.options[i].text;
        toField.options[insertIndex].value = selectedOptions.options[i].value;
        toField.options[insertIndex].selected = true;
    }
}

function getRadioValue(radioObj) {
    var i;

    if (!radioObj.length) {
        if (radioObj.checked) {
            return radioObj.value;
        }
    }

    for (i = 0; i < radioObj.length; i++) {
        if (radioObj[i].checked) {
            if (radioObj[i].value) {
                return radioObj[i].value;
            } else {
                return i;
            }
        }
    }
    return null;
}


function cat_members(obj_sel, obj_mem) {
    var len = obj_sel.length;
    var i;
    var members = '';

    if (len > 0) {
        members = obj_sel.options[0].text;
        for (i = 1; i < len; i++) {
            members = members + '#' + obj_sel.options[i].text;
        }
        obj_mem.value = members;
    }
}

// Common

function toNumber(str, start, end) {
    var tempVal = 0,
        i,
        c;

    for (i = start; i < end; i++) {
        c = str.charAt(i);
        if (c < '0' || c > '9') return - 1;

        tempVal = tempVal * 10 + (c - '0');
    }

    return tempVal;
}



// IP

function alertWinIP(IP, errmsg) {
    alert(IP + ' ' + errmsg);
}

function stringToNumber(str) {
    return toNumber(str, 0, str.length);
}

function verifyIPAndMask(cntrl, errmsg) {
    var i,
        tokens = [],
        ip_mask_str = cntrl.value,
        parts,
        first,
        second;

    tokens = ip_mask_str.split(".");

    if (tokens.length < 4) {
        alertWinIP(cntrl.value, errmsg);
        return false;
    }

    for (i = 0; i < 3; i++) { // check the x.x.x... prefix
        if ((stringToNumber(tokens[i]) < 0) || (stringToNumber(tokens[i]) > 255)) {
            alertWinIP(cntrl.value, errmsg);
            return false;
        }
    }

    if (tokens.length == 4) {
        if ((stringToNumber(tokens[3]) >= 0) && (stringToNumber(tokens[i]) <= 255)) { //x.x.x.x
            return true;
        }

        if (tokens[3].indexOf("*") == 0) { //x.x.x.*
            return true;
        }

        parts = [];
        parts = tokens[3].split("/");
        if (parts.length == 2) { //x.x.x.x/x
            if ((stringToNumber(parts[0]) < 0) || (stringToNumber(parts[0]) > 255)) {
                alertWinIP(cntrl.value, errmsg);
                return false;
            }
            if ((stringToNumber(parts[1]) < 0) || (stringToNumber(parts[1]) > 32)) {
                alertWinIP(cntrl.value, errmsg);
                return false;
            }
            return true;
        }

        parts = tokens[3].split("-");
        if (parts.length == 2) { //x.x.x.[x-x]
            first = stringToNumber(parts[0].substring(1, parts[0].length));
            second = stringToNumber(parts[1].substring(0, parts[1].length - 1));
            if ((parts[0].indexOf("[") == 0) && (first >= 0) && (first <= 255) && (parts[1].indexOf("]") == parts[1].length - 1) && (second >= 0) && (second <= 255) && (first <= second)) {
                return true;
            }
        }
    }

    if (tokens.length == 7) {
        for (i = 0; i < 7; i++) {
            if (i != 3) {
                if ((stringToNumber(tokens[i]) < 0) || (stringToNumber(tokens[i]) > 255)) {
                    alertWinIP(cntrl.value, errmsg);
                    return false;
                }
            }
        }

        parts = [];
        parts = tokens[3].split("/");
        if (parts.length == 2) { //x.x.x.x/x.x.x.x
            if ((stringToNumber(parts[0]) < 0) || (stringToNumber(parts[0]) > 255)) {
                alertWinIP(cntrl.value, errmsg);
                return false;
            }
            if ((stringToNumber(parts[1]) < 0) || (stringToNumber(parts[1]) > 255)) {
                alertWinIP(cntrl.value, errmsg);
                return false;
            }
            return true;
        }
        parts = tokens[3].split("-");
        if (parts.length == 2) { // x.x.x.x-x.x.x.x
            first = stringToNumber(parts[0].substring(0, parts[0].length));
            second = stringToNumber(parts[1].substring(0, parts[1].length));
            if ((first >= 0) && (first <= 255) && (second >= 0) && (second <= 255)) {
                return true;
            }
        }
    }

    alertWinIP(cntrl.value, errmsg);
    return false;
}


