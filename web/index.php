<!DOCTYPE html>
<html>
<head>
	<script src="js/jquery-3.3.1.min.js"></script>
	<link href="css/bootstrap2.css" rel="stylesheet" />
	<link href="css/bootsrap-theme.css" rel="stylesheet" />
	<link href="css/style.css" rel="stylesheet" />
	<script src="js/bootstrap.js"></script>
	<title>Snort Alarms</title>
</head>
<header>
	<h1>Snort Alarms</h1>
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
      			<div class="form" style="max-width: 1050px;">
      			
      			<!-- TABLE <<< -->
      			<div class="panel panel-default">
      				<div class="panel-heading">Alarms:
						<?php
							if (!isset($_GET['order']) ) {
								$order = "asc";
							}else {
							  $order = $_GET['order'];
							}
							if($order == 'asc'){
								echo '<a class="btn btn-primary btn-s" href="'.$_SERVER['PHP_SELF'].'?order=desc">Order: desc</a>';
							}
							else{
								echo '<a class="btn btn-primary btn-s" href="'.$_SERVER['PHP_SELF'].'?order=asc">Order: asc</a>';
							}
						?>
					</div>
      				<div class="table-responsive">
      					<table class="table" width="100%" border="0" cellpadding="0" cellspacing="0">
      						<tr>
							<th style="width: 3%;">cid</th>
							<th style="width: 30%;">alarm info</th>
							<th style="width: 18%;">timestamp</th>
							<th style="width: 8%;">src_ip</th>
							<th style="width: 8%;">dst_ip</th>
							<th style="width: 5%;">ip_proto</th>
							<th style="width: 5%;">src_port</th>
							<th style="width: 5%;">dst_port</th>
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
								if (!isset($_GET['order']) ) {
									$order = "asc";
								}else {
								  $order = $_GET['order'];
								}
																	
								$all_data = $conn->query("SELECT * FROM iphdr")or die(mysql_error());
								$number_of_rows = $all_data->num_rows;
								$result = $conn->query("SELECT * FROM iphdr order by cid $order  LIMIT $startrow, 8")or die(mysql_error());
								if ($result->num_rows > 0) {
									echo $number_of_rows." results";
									while($row = $result->fetch_assoc()) {
										echo "<tr><td>" . $row['cid']. "</td>";
										$row_cid = $row['cid'];
										$event_sql = $conn->query("SELECT * FROM event where cid=$row_cid")or die(mysql_error());
										$event_row = $event_sql->fetch_assoc();
										$signature_event = $event_row['signature'];
										$signature_sql = $conn->query("SELECT * FROM signature where sig_id=$signature_event")or die(mysql_error());
										$signature_row = $signature_sql->fetch_assoc();
										echo "<td>" . $signature_row['sig_name']. "</td>";
										echo "<td>" . $event_row['timestamp']. "</td>";
										echo "<td>" . long2ip($row['ip_src']). "</td>";
										echo "<td>" . long2ip($row['ip_dst']). "</td>";

										if($row['ip_proto'] == 1){
											echo "<td>ICMP</td>";
										}
										else if($row['ip_proto'] == 6){
											echo "<td>TCP</td>";
											$tcp_sql = $conn->query("SELECT * FROM tcphdr where cid=$row_cid")or die(mysql_error());
											$tcp_row = $tcp_sql->fetch_assoc();
											echo "<td>" . $tcp_row['tcp_sport']. "</td>";
											echo "<td>" . $tcp_row['tcp_dport']. "</td></tr>";
										}
										else if($row['ip_proto'] == 17){
											echo "<td>UDP</td>";
											$udp_sql = $conn->query("SELECT * FROM udphdr where cid=$row_cid")or die(mysql_error());
											$udp_row = $udp_sql->fetch_assoc();
											echo "<td>" . $udp_row['udp_sport']. "</td>";
											echo "<td>" . $udp_row['udp_dport']. "</td></tr>";
										}
										else{
											echo "<td>".$row['ip_proto']."</td>/tr>";
										}


									}
								} else {
									echo "0 results";
								}
								echo "</tr></table></div></div>";
								$conn->close();
				#echo "<h1>a".$number_of_rows."</h1>";
				if($order == 'asc' and $number_of_rows>8){
					if($number_of_rows-$startrow-8>0){
					echo '<div class="pull-right"><a class="btn btn-default btn-s" href="'.$_SERVER['PHP_SELF'].'?startrow='.($startrow+8).'&order='.$order.'">Next</a></div>';
					}
					$prev = $startrow - 8;
					if ($prev >= 0)
						echo '<a class="btn btn-default btn-s" href="'.$_SERVER['PHP_SELF'].'?startrow='.$prev.'&order='.$order.'">Previous</a>';
				}
				else if($number_of_rows>8){
					if($number_of_rows-$startrow-8>0){
					echo '<a class="btn btn-default btn-s" href="'.$_SERVER['PHP_SELF'].'?startrow='.($startrow+8).'&order='.$order.'">Previous</a>';
					}
					$next = $startrow - 8;
					if ($next >= 0)
						echo '<div class="pull-right"><a class="btn btn-default btn-s" href="'.$_SERVER['PHP_SELF'].'?startrow='.$next.'&order='.$order.'">Next</a></div>';
				}
				?>
      		</div>
      	</div>
      </div>
     
     <footer align="bottom"> &copy; YTU </footer>
  </body>
</html>
