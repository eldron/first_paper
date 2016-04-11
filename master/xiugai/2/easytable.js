function EasyTable(oTableElement){
	SelectableTableRows.call(this, oTableElement, false);

        oThis = this;
        this._ondblclick = function (e) {
		if (e == null) e = oTableElement.ownerDocument.parentWindow.event;
		oThis.dblclick(e);
	};

        if (oTableElement.addEventListener)
		oTableElement.addEventListener("dblclick", this._ondblclick, false);
	else if (oTableElement.attachEvent)
		oTableElement.attachEvent("ondblclick", this._ondblclick);
}

EasyTable.prototype = new SelectableTableRows;
/* SelectableElements
   if (oElement == null) return;  ensure new construtor without parameter success
   */

EasyTable.prototype.dblclick = function (e) {
  if (this.ondblclick && typeof this.ondblclick == "function") this.ondblclick(e);
}

EasyTable.prototype.addRow = function (tr){
    this._htmlElement.tBodies[0].appendChild(tr);
    this.setItemSelectedUi(tr,false);
    this.setItemSelected(tr,true);
}


EasyTable.prototype.removeRow =  function(){
  if(this.getSelectedIndexes().length>0){
    var src = this.getSelectedItems()[0];
    var current = this.getItemIndex(src);
    this.setItemSelected(src,false);
    this._htmlElement.tBodies[0].removeChild(src);
    var count = this.getItems().length;
    if(current>=(count-1))  current = count - 1;
    if(count>1) this.setItemSelected(this.getItem(current),true);
  }
}

EasyTable.prototype.upRow =  function(){
  if(this.getSelectedIndexes().length>0){
    var src = this.getSelectedItems()[0];
    var current = this.getItemIndex(src);
    if(current>1){
      ref = this.getItem(current-1);
      this._htmlElement.tBodies[0].insertBefore(src,ref);
    }
  }
}

EasyTable.prototype.downRow =  function(){
  if(this.getSelectedIndexes().length>0){
    var src = this.getSelectedItems()[0];
    var current = this.getItemIndex(src);
    var count = this.getItems().length;
    if(current<count-1){
      ref = this.getItem(current+1);
      this._htmlElement.tBodies[0].insertBefore(ref,src);
    }
  }
}

EasyTable.prototype.getCloneSelectedRow = function(){
  if(this.getSelectedIndexes().length>0){
     var src = this.getSelectedItems()[0];
//     alert(src.childNodes[1].firstChild.data+';');
     var tr = src.cloneNode(true);
     return tr;
  }else return null;
}

EasyTable.prototype.getSelectedRow = function(){
  if(this.getSelectedIndexes().length>0){
     var src = this.getSelectedItems()[0];
     return src;
  }else return null;
}

EasyTable.prototype.getSelectedCellText = function(cellIndex){
  if(this.getSelectedIndexes().length>0){
     var src = this.getSelectedItems()[0];
     if(navigator.appName==("Microsoft Internet Explorer")){
      return src.cells(cellIndex).innerText;
     }else if(navigator.appName.indexOf("Firefox")){
      return src.cells[cellIndex].textContent;
     }
  }else return null;
}

EasyTable.prototype.haveThisRowByCell = function(cellIndex,askValue){
  var items = this.getItems();
  var found = false;
  for(var i=0;i<items.length;i++){
  if(navigator.appName==("Microsoft Internet Explorer")){
     if(items[i].cells(cellIndex).innerText.trim()==askValue){
      found = true;
      break;
   }
     }else if(navigator.appName.indexOf("Firefox")){
      if(items[i].cells[cellIndex].textContent.trim()==askValue){
      found = true;
      break;
    }
     }
  }
  return found;
}

EasyTable.prototype.haveThisRow = function(askValue){
 return this.haveThisRowByCell(0,askValue);
}

var Tab = new Object();
Tab.switchTabPage  = function (currentPageId,pageIdArray){
  for(var count = 0 ; count < pageIdArray.length ; count++){
    if(pageIdArray[count]!=currentPageId){
      Element.removeClassName(pageIdArray[count],"selected");
      document.getElementById(pageIdArray[count]).style.color="#0066FF";
      Element.addClassName(pageIdArray[count]+'_page',"tabunselected");
    }
  }
  Element.addClassName(currentPageId,"selected");
  document.getElementById(currentPageId).style.color="#ffffff";
  Element.removeClassName(currentPageId+'_page',"tabunselected");
}

var Dialog = new Object();
Dialog.show = function(url,params,width){
   var infoDiv = $('info');
   var shutterDiv = $('shutter');
   if(width) infoDiv.style.width = width+"px";
   else infoDiv.style.width = "430px";
   infoDiv.style.display = "block";
   shutterDiv.className = "shutter";
   infoDiv.className = "info";
   new Ajax.Updater('info',url, {method: 'post', parameters: params,displayLoading:true,evalScripts:true});
}

Dialog.close = function(){
    var infoDiv = $('info');
    var dialogContentDiv = $('xboxcontent');
    var shutterDiv = $('shutter');

    dialogContentDiv.innerHTML = "";

    infoDiv.className = "";
    shutterDiv.className = "";
    infoDiv.style.display = "none";
}
