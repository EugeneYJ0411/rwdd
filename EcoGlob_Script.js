// Check if the username and password is set
$user = isset($_REQUEST['username']) ? $_REQUEST['username'] : null;
$pass = isset($_REQUEST['password']) ? $_REQUEST['password'] : null;
$sql="SELECT * FROM users WHERE username='$user' and userpassword='$pass'";
// Check if the username and password is the same in database
$result=mysqli_query($conn,$sql);
if(mysqli_num_rows($result) > 0) {
    $_SESSION['user'] = $user;
    header("location: protected.php");
}
 if(mysqli_num_rows($result) < 0) {
  header("Location: login.php");
}
