



function setProperty(obj, property, value) {
    var evalStr = "obj." + property + "=" + value + ";";
    eval(evalStr);
}



function changeStyle(obj, property, value) {
    setProperty(obj, "style." + property, value);
}


function hideElementsById(idArray, hide, hideChildren) {
    var rootObj,
        i,
        j,
        hideText = hide ? "'none'": "''";

    for (i = 0; i < idArray.length; i++) {
        rootObj = document.getElementById(idArray[i]);
        if (rootObj) changeStyle(rootObj, "display", hideText);
        if (rootObj == null) continue;

        if (hideChildren) {
            for (j = 0; j < rootObj.childNodes.length; j++) {
                try {
                    changeStyle(rootObj.childNodes.item(j), "display", hideText);
                } catch(e) {
                    continue;
                }
            }
        }
    }
}


function hideSection(controlObj, idArray) {
    var hidden = !(document.getElementById(idArray[0]).style.display == 'none');

    hideElementsById(idArray, hidden);

    if (hidden) {
        controlObj.src = "/images/twistie_collapsed.gif";
    } else {
        controlObj.src = "/images/twistie_expanded.gif";
    }
}


function findInArray(thisArray, elementToFind) {
    var index = -1;

    for (var i = 0; i < thisArray.length; i++) {
        if (thisArray[i] == elementToFind) {
            index = i;
            break;
        }
    }
    return index;
}

