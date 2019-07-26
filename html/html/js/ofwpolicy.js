



// __locate_img_element - helper function for toggle_category & toggle_section
function __locate_img_element(obj) {
    var aImgs;

    if (obj.tagName.toLowerCase() == "img") return obj;

    aImgs = jQuery(obj).find("img");
    if (!aImgs.length) return null;

    return aImgs[0];
}

// toggle_category - expand/collapse category
// Note: this may be called with obj as either the <tr> or <img> element.
function toggle_category(obj) {
    var img = __locate_img_element(obj);
    if (!img) return;

    hideSection(img, ["b_" + img.id.slice("a_".length)]);
    updateTreeState(img);
    saveTreeState();
}


function updateTreeState(obj) {
    var expand = (obj.src.search(/twistie_expanded.gif$/) != -1) ? 1 : 0,
        stateID = obj.id.slice("a_".length);

    if (expand) {
        if (findInArray(treeState, stateID) < 0) treeState[treeState.length] = stateID;
    } else {
        treeState.splice(findInArray(treeState, stateID), 1);
    }
}

function saveTreeState() {
    var newCookie = treeState.join("&");
    setCookie(g_treeCookieName, newCookie);
}

