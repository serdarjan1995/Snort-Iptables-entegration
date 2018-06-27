<!DOCTYPE html>
<html>
<head>
	<script src="js/jquery-3.3.1.min.js"></script>
	<link href="css/bootstrap2.css" rel="stylesheet" />
	<link href="css/bootsrap-theme.css" rel="stylesheet" />
	<link href="css/style.css" rel="stylesheet" />
	<script src="js/bootstrap.min.js"></script>
	<title>Iptables Rules</title>
</head>
<header>
	<h1>Iptables Rules</h1>

</header>
<body>

    <nav class="navbar navbar-default">
	<div class="container-fluid">
		<div class="navbar-header">
		  <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1" aria-expanded="false">
			<span class="sr-only">Toggle navigation</span>
			<span class="icon-bar"></span>
		  </button>
		  <a class="navbar-brand" href="#">Main Page</a>
		</div>
		<div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">

			<ul class="nav navbar-nav">
			<li><a href="index.php" >Snort Alarms</a></li>
			<li><a href="rules.php" >Iptables Rules</a></li>
			<li><a href="oldRules.php" >Iptables Expired Rules</a></li>
			</ul>
			 
		</div><!-- /.navbar-collapse -->
	</div><!-- /.container-fluid -->
</nav>
	   
      <div class="container">
      		<div class="col-md-12">
      			<div class="form" style="max-width: 850px;">
      			
      			<!-- TABLE <<< -->
      			<div class="panel panel-default">
      				<div class="panel-heading">Current Rules:
						<a href="" class="btn btn-info btn-s" data-toggle="modal" data-target="#newIpTablesRule">Add New Rule</a>
					</div>
      				<div class="table-responsive">
      					<table class="table" width="100%" border="0" cellpadding="0" cellspacing="0">
      						<tr>
							<th style="width: 8%;">ipsrc</th>
							<th style="width: 8%;">ipdst</th>
							<th style="width: 5%;">protocol</th>
							<th style="width: 5%;">s_port</th>
							<th style="width: 5%;">d_port</th>
							<th style="width: 20%;">blocked_time</th>
							<th style="width: 8%;">delete_after</th>
							
      						</tr>
								<tr>
								<?php
								$servername = "localhost";
								$username = "root";
								$password = "root";
								$dbname = "snort";
								// Create connection
								$conn = new mysqli($servername, $username, $password, $dbname);
							
								// Check connection
								if ($conn->connect_error) {
									die("Connection failed: " . $conn->connect_error);
								} 
								#echo "Connected successfully";
								if (!isset($_GET['startrow']) or !is_numeric($_GET['startrow'])) {
									$startrow = 0;
								}else {
								  $startrow = (int)$_GET['startrow'];
								}
																	
								$all_data = $conn->query("SELECT * FROM blocked_ip")or die(mysql_error());
								$number_of_rows = $all_data->num_rows;
								$result = $conn->query("SELECT * FROM blocked_ip LIMIT $startrow, 8")or die(mysql_error());
								if ($result->num_rows > 0) {
									echo $number_of_rows." results";
									while($row = $result->fetch_assoc()) {
										echo "<tr><td>" . long2ip($row['ipsrc']). "</td>";
										echo "<td>" . long2ip($row['ipdst']). "</td>";

										if($row['protocol'] == 1){
											echo "<td>ICMP</td>";
										}
										else if($row['protocol'] == 6){
											echo "<td>TCP</td>";
										}
										else if($row['protocol'] == 17){
											echo "<td>UDP</td>";
										}
										else if($row['protocol'] == ''){
											echo "<td>ALL</td>";
										}
										else{
											echo "<td>".$row['protocol']."</td>";
										}
										echo "<td>" . $row['s_port']. "</td>";
										echo "<td>" . $row['d_port']. "</td>";
										echo "<td>" . $row['blocked_time']. "</td>";
										echo "<td>" . $row['delete_after']. " mins</td>";
									}
								} else {
									echo "0 results";
								}
								echo "</tr></table></div></div>";
								$conn->close();

					if($number_of_rows>8){
						if($number_of_rows-$startrow-8>0){
						echo '<div class="pull-right"><a class="btn btn-default btn-s" href="'.$_SERVER['PHP_SELF'].'?startrow='.($startrow+8).'&order='.$order.'">Next</a></div>';
						}
						$prev = $startrow - 8;
						if ($prev >= 0)
							echo '<a class="btn btn-default btn-s" href="'.$_SERVER['PHP_SELF'].'?startrow='.$prev.'&order='.$order.'">Previous</a>';
					}
				?>
      		</div>
      	</div>
      </div>
					
					
			<!-- Modal -->
	<div id="newIpTablesRule" class="modal fade" role="dialog">
	  <div class="modal-dialog" role="document">
	
	    <!-- Modal content-->
	    <div class="modal-content">
	      <div class="modal-header">
	        <button type="button" class="close" data-dismiss="modal">&times;</button>
	        <h4 class="modal-title">New Iptables Rule:</h4>
	      </div>
	      <div class="modal-body">
	      
	        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>" method="POST">
					<div class="form-group">
						<div><span class="input-group-addon">Source IP</span>
						<input class="form-control" type="text" name="src_ip" value=""/></div>
						<div><span class="input-group-addon">Destination IP</span>
						<input class="form-control" type="text" name="dst_ip" value=""/></div>
						<div><span class="input-group-addon">IP protocol</span>
						<input class="form-control" type="text" name="ip_proto" value=""/></div>
						<div><span class="input-group-addon">Source port</span>
						<input class="form-control" type="number" min="0" max="65535" name="s_port" value=""/></div>
						<div><span class="input-group-addon">Destination port</span>
						<input class="form-control" type="number" min="0" max="65535" name="d_port" value=""/></div>
						<div><span class="input-group-addon">Delete after</span>
						<input class="form-control" type="number" min="1" step="1" name="delete_after" value=""/></div>
        			</div>
					<button type="submit" class="btn btn-default" >Submit</button>
     	</form>
    
	      </div>
	      <div class="modal-footer">
			
	        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
	      </div>
	    </div>
	
	  </div>
	</div><!-- modal end -->
		<?php
		// define variables and set to empty values
		$src_ip = $dst_ip = $ip_proto = $delete_after = "";
		if ($_SERVER["REQUEST_METHOD"] == "POST") {
		  $src_ip = test_input($_POST["src_ip"]);
		  $dst_ip = test_input($_POST["dst_ip"]);
		  $ip_proto = test_input($_POST["ip_proto"]);
		  $s_port = test_input($_POST["s_port"]);
		  $d_port = test_input($_POST["d_port"]);
			if( !strcasecmp($ip_proto, "") ) $ip_proto ='all';
			if( !strcasecmp($ip_proto, "icmp") ) $ip_proto = 1;
			if( !strcasecmp($ip_proto, "tcp") ) $ip_proto = 6;
			if( !strcasecmp($ip_proto, "udp") ) $ip_proto = 17;
		  $delete_after = test_input($_POST["delete_after"]);
			if ( filter_var($src_ip, FILTER_VALIDATE_IP) && filter_var($dst_ip, FILTER_VALIDATE_IP) ) {
					if($ip_proto== 6 or $ip_proto==17){
						$iptables_rule = "iptables -A FORWARD -s ".$src_ip." -d ".$dst_ip." -p ". $ip_proto." --sport ".$s_port." --dport ".$d_port." -j DROP";
					}
					else{
						$iptables_rule = "iptables -A FORWARD -s ".$src_ip." -d ".$dst_ip." -p ". $ip_proto." -j DROP";
					}
					$connection = ssh2_connect('192.168.111.135', 22);
					ssh2_auth_password($connection, 'root', 'rootfirewall');
					if (!$connection){ showModal('SSH Connection failed',''); die('');}
					$stream = ssh2_exec($connection, $iptables_rule);
					stream_set_blocking($stream, true);
					$stream_out = ssh2_fetch_stream($stream, SSH2_STREAM_STDIO);
					if( stream_get_contents($stream_out) == "" ){
						$message = "SSH successfully exported rule!";
						$servername = "localhost";
						$username = "root";
						$password = "root";
						$dbname = "snort";

						// Create connection
						$conn = new mysqli($servername, $username, $password, $dbname);
						// Check connection
						if ($conn->connect_error) {
							showModal('',"DB Connection failed: " . $conn->connect_error);
							if($ip_proto== 6 or $ip_proto==17){
								$iptables_rule = "iptables -D FORWARD -s ".$src_ip." -d ".$dst_ip." -p ". $ip_proto." --sport ".$s_port." --dport ".$d_port." -j DROP";
							}
							else{
								$iptables_rule = "iptables -D FORWARD -s ".$src_ip." -d ".$dst_ip." -p ". $ip_proto." -j DROP";
							}
							$stream = ssh2_exec($connection, $iptables_rule);
							die("");
						} 
						if($ip_proto == 'all'){
							$sql = "INSERT INTO blocked_ip (ipsrc, ipdst, protocol,blocked_time,delete_after)
							VALUES (".ip2long($src_ip).", ".ip2long($dst_ip).", NULL, '".date('Y-m-d H:i:s')."', ".$delete_after.")";
						}
						else if(($ip_proto== 6 or $ip_proto==17) and ($s_port!=NULL and $d_port!=NULL)){
							$sql = "INSERT INTO blocked_ip (ipsrc, ipdst, protocol,blocked_time,delete_after,s_port,d_port)
							VALUES (".ip2long($src_ip).", ".ip2long($dst_ip).", ".$ip_proto.", '".date('Y-m-d H:i:s')."', ".$delete_after.", ".$s_port.", ".$s_port.")";
						}
						else{
							$sql = "INSERT INTO blocked_ip (ipsrc, ipdst, protocol,blocked_time,delete_after)
							VALUES (".ip2long($src_ip).", ".ip2long($dst_ip).", ".$ip_proto.", '".date('Y-m-d H:i:s')."', ".$delete_after.")";
						}

						if ($conn->query($sql) === TRUE) {
							$message2 =  "New record added to database successfully!";
						} else {
							$message2 = "Error: " . $sql . "<br>" . $conn->error . "</br> Rollback rule";
							if($ip_proto== 6 or $ip_proto==17){
								$iptables_rule = "iptables -D FORWARD -s ".$src_ip." -d ".$dst_ip." -p ". $ip_proto." --sport ".$s_port." --dport ".$d_port." -j DROP";
							}
							else{
								$iptables_rule = "iptables -D FORWARD -s ".$src_ip." -d ".$dst_ip." -p ". $ip_proto." -j DROP";
							}
							$stream = ssh2_exec($connection, $iptables_rule);
						}
						showModal($message,$message2);
						$conn->close();
						ssh2_disconnect($connection);
					}
			} else {
				showModal("Not a valid IP address",'');
			}


		}
		function showModal($message,$message2){
				echo"		<!-- Modal -->
					<div class='modal fade' id='alertmodal' tabindex='-1' role='dialog' aria-labelledby='exampleModalLabel' aria-hidden='true'>
					  <div class='modal-dialog' role='document'>
						<div class='modal-content'>
						  <div class='modal-header'>
							<h5 class='modal-title' id='exampleModalLabel'>Result</h5>
							<button type='button' class='close' data-dismiss='modal' aria-label='Close'>
							  <span aria-hidden='true'>&times;</span>
							</button>
						  </div>
						  <div class='modal-body'>"
							.$message."<br>".$message2.
						  "</div>
						  <div class='modal-footer'>
							<button type='button' class='btn btn-secondary' data-dismiss='modal'>Close</button>
						  </div>
						</div>
					  </div>
					</div>";
					echo "<script type='text/javascript'>
						$(document).ready(function(){
						$('#alertmodal').modal('show');
						});
						</script>";
			}
					
		function test_input($data) {
		  $data = trim($data);
		  $data = stripslashes($data);
		  $data = htmlspecialchars($data);
		  return $data;
		}
				
		?>			
     
     <footer align="bottom"> &copy; YTU </footer>
  </body>
</html>
