

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


