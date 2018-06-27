<!DOCTYPE html>
<html>
<head>
	<script src="js/jquery-3.3.1.min.js"></script>
	<link href="css/bootstrap2.css" rel="stylesheet" />
	<link href="css/bootsrap-theme.css" rel="stylesheet" />
	<link href="css/style.css" rel="stylesheet" />
	<script src="js/bootstrap.min.js"></script>
	<title>Iptables Expired Rules</title>
</head>
<header>
	<h1>Iptables Expired Rules</h1>

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
      			<div class="form" style="max-width: 900px;">
      			
      			<!-- TABLE <<< -->
      			<div class="panel panel-default">
      				<div class="panel-heading">Expired Rules:
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
							<th style="width: 20%;">unblocked_after</th>
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
																	
								$all_data = $conn->query("SELECT * FROM deleted_rule")or die(mysql_error());
								$number_of_rows = $all_data->num_rows;
								$result = $conn->query("SELECT * FROM deleted_rule LIMIT $startrow, 8")or die(mysql_error());
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
										echo "<td>".$row['s_port']."</td>";
										echo "<td>".$row['d_port']."</td>";
										echo "<td>" . $row['blocked_time']. "</td>";
										echo "<td>" . $row['unblocked_time']. "</td>";
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
				
     
     <footer align="bottom"> &copy; YTU </footer>
  </body>
</html>
