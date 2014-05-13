#!/usr/bin/env php
<?php
/**
 * @file
 * This script is used to analyse apache access logs an store them in a SQLite
 * database, which then can be used to generate url files for seige to do
 * performance test on web-servers.
 *
 *
 * Supported options is:
 *   -c (count):         Count ip, url
 *
 *   -x (count options): Limit the count to e.g url '/user' and dump ips on the
 *                       screen (verbose).
 *
 *   -d (domain):        Domain to prefix urls (http(s)://test.dk).
 *
 *   -i (input):         File to parse into the SQLite database (apache access file).
 *   -o (output):        If pattern to output (urls_{n}.txt).
 *
 *   -g (group):         Group by ip (enter no of files to group into, files may
 *                       not have same size).
 *
 *   -f (filter):        Filter out URLs based on regex in the output files.
 *
 *   -l (lines):         Write x lines into each file.
 *
 *   -p (pattern):       How to parse the access log ($ip, $time, $url, $code). Split
 *                       on space, where is the parts located on a log line.
 *
 *   -t (time):          Time format in the log
 *
 * Usage:
 *   Read log: ./access2siege.php -i access.log -p "1,4,7,9" -t "d/m/y:H:i:s"
 *   Ouput:    ./access2siege.php -o "urls_{n}.txt" -d https://foo.com -l 50000
 *             ./access2siege.php -o "urls_{n}.txt" -f 'css$' -d https://foo.com -l 50000
 *   Stats:    ./access2siege.php -c urls
 *             ./access2siege.php -c urls -x '/user'
 *             ./access2siege.php -c ips
 *             ./access2siege.php -c ips -x verbose
 *
 * @author Jesper Kristensen (cableman@linuxdev.dk)
 *
 */

// Check if its CLI else exit fast.
define('ISCLI', PHP_SAPI === 'cli');
if (!ISCLI) {
  echo '<b>This script is only for command line use.<b>';
  exit(0);
}

/**
 * Main class that starts the script in its constructor and handles the basic
 * logic.
 */
class Access2Seige {
  private $options = array();

  function __construct() {
    $this->getOptions();
  }

  /**
   * Parses command line options and takes action base on the paremeters.
   *
   * @throws Exception
   */
  private function getOptions() {
    $this->options = getopt("c:d:i:o:g:l:p:t:x:f:");
    /**
     * Input data.
     **/
    if (isset($this->options['i'])) {
      if (!file_exists($this->options['i'])) {
        throw new Exception('Input file do not exists or is not readable!');
      }
      // Input require -p and -t with -i
      if (!isset($this->options['p']) || !isset($this->options['t'])) {
        throw new Exception('Log line pattern (-p) and time format (-t) is required together with input (-i).');
      }

      // @todo verify that the parameters have the right format.

      // All parameters required found to parse apache access log
      $this->parseLog();
      exit(0);
    }

    /**
     * Output data.
     **/
    if (isset($this->options['o'])) {
      if (!isset($this->options['d'])) {
        throw new Exception('Domain (-d) is required when generating output files.');
      }
      if (isset($this->options['l']) || isset($this->options['g'])) {
        if (isset($this->options['l'])) {
          // Put x lines in each file.
          $db = new accessDB();
          $file = new A2SFile(FALSE, $this->options['d'], 'lines', $this->options['o']);
          // Read 1000 lines at a time and write them to output.
          while ($urls = $db->nextUrls(1000)) {
            $urls = $this->filterURLs($urls);
            echo '#';
            $file->write($urls, $this->options['l']);
          }
          echo "\nAll files have been created\n";
          exit(0);
        }
        else if (isset($this->options['g'])) {
          // Find the number of ips to put in each file
          $db = new accessDB();
          $current_file_no = 1;
          $ip_in_file = round($db->countIps() / $this->options['g']);
          if ($db->countIps() < $this->options['g']) {
            throw new Exception('Too few IPs found to split urls into ' . $this->options['g'] . ' files');
          }
          // Create first file (or the file).
          $file = new A2SFile(FALSE, $this->options['d']);
          $ip_count = 0;
          echo $db->countIps(),' IPs found in the database.',"\nProgress: ";
          foreach ($db->getIps() as $ip) {
            $where = array();
            $where[] = array('ip', $ip, '=');
            // Read 1000 lines at a time and write them to output.
            while ($urls = $db->nextUrls(1000, $where, TRUE)) {
              $urls = $this->filterURLs($urls);
              echo '#';
              $file->write($urls);
            }
            $db->reset(); // Reset next off-set.
            $ip_count++;
            if ($ip_count == $ip_in_file) {
              if ($current_file_no == $this->options['g']) {
                $file->close();
                echo "\nAll files have been created\n";
                exit(0);
              }
              else {
                // Next file.
                $file->next();
                $current_file_no++;
                $ip_count = 0;
              }
            }
          }
        }
      }
      else {
        throw new Exception('No output format selected (-l or -g).');
      }
      exit(0);
    }

    /**
     * Stats on the database.
     **/
    if (isset($this->options['c'])) {
      $db = new accessDB();
      $limit = isset($this->options['x']) ? $this->options['x'] : NULL;
      switch ($this->options['c']) {
        case 'ips':
          if ($limit == 'verbose') {
            // Dump the actually ips onto the screen.
            print_r($db->getIps());
          }
          throw new Exception('The database has \'' . $db->countIps() . '\' IPs');
          break;

        case 'urls':
          throw new Exception('The database has \'' . $db->countUrls($limit) . '\' URLs');
          break;

        default:
          throw new Exception('Unknown stats opreation given.');
          break;
      }
      exit(0);
    }
    throw new Exception('No operation defined (-o, -i or -c).');
  }

  /**
   * Parse the access log file given as input based on the pattern (-p) and time
   * format (-t).
   */
  private function parseLog() {
    $file = new A2SFile($this->options['i']);
    $db = new accessDB();

    $progress = 0;

    // Read the file line for line.
    while ($raw_line = $file->read()) {
      $line = explode(' ', $raw_line);
      $index = explode(',', $this->options['p']);

//      print_r($line);
//      print_r($index);
//      die;

      // Get values form the line.
      $ip = isset($line[$index[0]]) ? $line[$index[0]] : NULL;
      $raw_time = isset($line[$index[1]]) ? $line[$index[1]] : NULL;
      $url = isset($line[$index[2]]) ? $line[$index[2]] : NULL;
      $code = isset($line[$index[3]]) ? $line[$index[3]] : NULL;
      if ($ip == NULL || $raw_time == NULL || $url == NULL || $code == NULL) {
        echo "\n",'Unable to parse: ',$raw_line,"\n";
        continue;
      }

      // Try to find the time.
      $raw_time = substr($raw_time, 1);
      $pos = strpos($this->options['t'], 'H') + 2;
      if ($pos == 0) {
        $time = substr($raw_time, $pos, 8);
        $date = substr($raw_time, 8);
      }
      else {
        $time = substr($raw_time, $pos * -1);
        $delimiter = strpos($this->options['t'], 'd') + 1;
        $date = substr($raw_time, 0, ($pos+1) * -1);
      }
      if (strpos($date, '/')) {
        $date = str_replace('/', '-', $date);
      }
      $time = strtotime($date . ' ' . $time . ' ' . substr($line[$index[1]+1], 0, -1));

      // Write collected data.
      $db->write($ip, $time, $url, $code);

      // Update progress
      if ($progress == 200) {
        echo "#";
        $progress = -1;
      }
      $progress++;
    }
    throw new Exception('Done reading file.');
  }

  private function filterURLs($urls) {
    if (isset($this->options['f'])) {
      $urls = preg_grep($this->options['f'], $urls, PREG_GREP_INVERT);
    }
    return $urls;
  }
}

/**
 * Handles reading and writing of data to flat files. If the first parameter is
 * a filename, it will assum that we are reading a file else writing output
 * files.
 *
 * It also has some enternal book keeping when write x number of lines to a
 * file (the -l script parameter).
 *
 */
class A2SFile {
  private $current_file_no = 1;
  private $current_line_no = 0;
  private $type = NULL; // can be lines.
  private $fh = NULL;
  private $domain = '';
  private $pattern = '';

  function __construct($file = FALSE, $domain = 'localhost', $type = NULL, $pattern = 'urls_{n}.txt') {
    $this->type = $type;
    $this->domain = $domain;
    $this->pattern = $pattern;
    $this->open($file);
  }

  function __destruct() {
    if ($this->fh != NULL) {
      $this->close();
    }
  }

  function open($file = FALSE) {
    if ($file) {
      $this->fh = fopen($file, "r");
    }
    else {
      $file = str_replace('{n}', $this->current_file_no, $this->pattern);
      $this->fh = fopen($file, "w");
    }
  }

  function close() {
    fclose($this->fh);
    $this->fh = NULL;
    $this->current_file_no++;
  }

  function read() {
    $buffer = fgets($this->fh, 4096);
    return $buffer;
  }

  function write($urls, $limit = 100000) {
    if ($this->type == 'lines') {
      foreach ($urls as $url) {
        fwrite($this->fh, $this->domain . $url . "\n");
        $this->current_line_no++;
        if ($this->current_line_no == $limit) {
          $this->next();
          $this->current_line_no = 0;
        }
      }
    }
    else {
      foreach ($urls as $url) {
        fwrite($this->fh, $this->domain . $url . "\n");
      }
    }
  }

  function next() {
    if ($this->fh != NULL) {
      $this->close();
    }
    $this->open();
  }
}

/**
 * Handles all interaction with the SQLite database, such as creation, reading
 * and writing records.
 *
 * The most advanced function is the nextUrls, which uses offset to fetch x rows
 * at a time. This is do to memory limitations in PHP, it turns out it requires
 * a lot of memory to have 4 milion urls in memory :-).
 */
class accessDB {
  private $db = NULL;
  private $counter = 0;

  function __construct() {
    $file = 'db.sqlite';
    if (!file_exists($file)) {
      $this->open($file);
      $this->create_tables();
    }
    else {
      $this->open($file);
    }
  }

  function __destruct() {
    $this->close();
  }

  private function open($file) {
    $this->db = new SQLite3($file);

    if($this->db){
      echo "Info: The database have been opened\n";
    } else {
      throw new Exception($db->lastErrorMsg());
    }
  }

  private function close() {
    $this->db->close();
    echo "Info: The database have been closed\n";
  }

  private function create_tables() {
    if ($this->db != NULL) {
      $query = 'CREATE TABLE access (id integer PRIMARY KEY, ' .
                                     'ip varchar(16), ' .
                                     'time integer, ' .
                                     'url text, ' .
                                     'code integer' .
                                     ')';
      if ($this->db->exec($query)) {
        echo "Info: A new database have been created\n";
      }
      else {
        throw new Exception($db->lastErrorMsg());
      }
    }
    else {
      echo "Error: No database found\n";
      exit(-1);
    }
  }

  public function reset($val = 0) {
    $this->counter = $val;
  }

  public function write($ip, $time, $url, $code) {
    $query = 'INSERT INTO access VALUES (null, "'.$ip.'", '.$time.', "'.$url.'", '.$code.')';
    if (!$this->db->exec($query)) {
      throw new Exception($db->lastErrorMsg());
    }
  }

  public function countUrls($limit = NULL) {
    $query = 'SELECT count(1) AS urls FROM access';
    if ($limit != NULL) {
      $query .= ' WHERE url = \'' . $limit . '\'';
    }
    $result = $this->db->query($query);
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
      return $row['urls'];
    }
  }

  public function countIps() {
    return count($this->getIps());
  }

  public function getIps() {
    // Static cache
    static $ips = array();
    if (!empty($ips)) {
      return $ips;
    }

    // Cache was empty, so try the database.
    $query = 'SELECT distinct ip FROM access;';
    $result = $this->db->query($query);
    if ($result) {
      while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $ips[] = $row['ip'];
      }
    }
    return $ips;
  }

  public function nextUrls($number = 500, array $where = array(), $order = FALSE) {
    $data = $this->next(array('url'), $number, $where, $order);
    if (!$data) {
      return FALSE;
    }
    $urls = array();
    foreach ($data as $url) {
      $urls[] = $url['url'];
    }
    return $urls;
  }

  private function next(array $fields, $number, array $where, $order) {
    // Build query.
    $query = 'SELECT ' . implode(',', $fields) . ' FROM access';
    $query .= $this->buildWhere($where);
    if ($order) {
      $query .= ' ORDER BY id';
    }
    $query .= ' LIMIT ' . $number . ' OFFSET ' . $this->counter;
    $this->counter += $number;

    // Get fields
    $data = array();
    $result = $this->db->query($query);
    if ($result) {
      while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        array_push($data, $row);
      }
    }
    return empty($data) ? FALSE : $data;
  }

  private function buildWhere(array $w) {
    if (!empty($w)) {
      $where = NULL;
      foreach ($w as $value) {
        if ($where != NULL) {
          $where .= ' AND ';
        }
        $where .= $value[0] . ' ' . $value[2] . ' \'' . $value[1] . '\'';
      }
      $where = ' WHERE ' . $where;
      return $where;
    }
  }
}

/*****
 * Execute the script by creating the Access2Seige object. Messages may be
 * returned form the script in form of exceptions, so catch them.
 ********/
try {
  $a2s = new Access2Seige();
}
catch (Exception $e) {
  echo $e->getMessage(),"\n";
}
exit(0);
