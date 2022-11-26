function showPass() {
  var x = document.getElementById("txtpass");
  if (x.type === "password") {
    x.type = "text";
  } else {
    x.type = "password";
  }
}
