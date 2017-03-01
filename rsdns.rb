#!/usr/bin/env ruby
#DNS enumeration tool for reports
require 'trollop'
require 'colorize'
require 'resolv'
require 'tty-command'
require 'logger'
require 'threadify'
require 'securerandom'
require 'csv'

class Rsdns

  attr_reader :domains, :mxrecords, :nsrecords, :resolved
  attr_reader :axfr_print, :axfr_file, :time

  def initialize
   
    @domains = []
    @mxrecords = []
    @nsrecords = []
    @resolved = []
    @full = []
    @axfr = []
    @axfr_dom = []
    @axfr_print = []
    @log = Logger.new('debug.log')
    @cmd = TTY::Command.new(output: @log)
    @time = Time.now.strftime("%d%b%Y_%H%M%S")
    @axfr_file = "axfr_#{@time}.txt"
    @wildcard = SecureRandom.hex
    @remove = []

  end

  def arguments
    @@opts = Trollop::options do 
      version "rsdns 1.01b".light_blue
      banner <<-EOS
      BANNER GOES HERE
      EOS

      opt :domain, "Choose a specific domain to enumerate", :type => String
      opt :domains, "List of all domains to enumerate", :type => String
      opt :subdomains, "subs", :type => String
      opt :dns_server, "Choose your own DNS server", :default => "8.8.8.8"
      opt :axfr, "Enable Zone Transfer Checking For All Domains"

      if ARGV.empty?
        puts "Need Help? Try ./rsdns --help or -h"
        exit
      end
    end
  end

  def domain
    if @@opts[:domain]
      @domains << @@opts[:domain].chomp
    end
  end

  def domainlist
    if @@opts[:domains]
    domain_list = File.readlines(@@opts[:domains]).map(&:chomp &&:strip)
      domain_list.each do |domain|
        @domains << domain.chomp #this chomp statement should be removed
      end
    end
  end

  def mx
    @domains.each do |d|
      Resolv::DNS.open do |dns|
        mx = dns.getresources d, Resolv::DNS::Resource::IN::MX
        mx.map! { |m| [m.exchange.to_s, IPSocket::getaddress(m.exchange.to_s)] } rescue mx.map! { |m|  [d, "NO MX RECORD FOR DOMAIN"] }
        mx.each { |m| @mxrecords << m }
      end
    end
  end

  def ns
    @domains.each do |domain|
      Resolv::DNS.open do |dns|
        ns = dns.getresources domain, Resolv::DNS::Resource::IN::NS
        ns.map! { |m| [m.name.to_s, IPSocket::getaddress(m.name.to_s)] } rescue ns.map! { |m|  "" }
        ns.each { |n| @axfr_dom << [n[0], n[1], domain] }
      end
    end
  end

  def remove_domain
    @axfr_dom.each { |a| @nsrecords << [a[0], a[1]] }
  end

  def wildcard_test
    if @@opts[:subdomains]
    resolver = Resolv::DNS.new(:nameserver => [@@opts[:dns_server], '8.8.4.4'])
    
    @domains.each do |domain|
      canary = "#{@wildcard}.#{domain}"
        resolver.each_address(canary) { |addr| @remove << domain if !addr.nil? } rescue ""
    end
  end

  def remove_wildcard
    if @remove.size > 0
      @remove.each do |dom|
        puts "#{dom} appears to be a wildcard domain, removing from further tests - Please manually check yourself!!".upcase.red.bold
          @domains = @domains - @remove
        end
      end
    end
  end

  def createsubs
    if @@opts[:subdomains]
    subs = File.readlines(@@opts[:subdomains]).map(&:chomp &&:strip).sort
      subs.each do |sub|
        @domains.each do |domain|
          @full << "#{sub}.#{domain}"
        end
      end
    end
  end

  def subdomains
    if @@opts[:subdomains]
      puts "\nSubdomain enumeration beginning at #{Time.now.strftime("%H:%M:%S")}".green.bold  

    resolver = Resolv::DNS.new(:nameserver => [@@opts[:dns_server], '8.8.4.4']) 
      @full.threadify do |name|
        resolver.each_address(name) { |addr| puts "#{name}\t#{addr}" if !addr.nil? ; @resolved << [name, addr] if !addr.nil? } rescue ""
        end   
      puts "Finished subdomain enumeration at #{Time.now.strftime("%H:%M:%S")}".green.bold
    end
  end
 
  def axfr
    if @@opts[:axfr]
      @axfr_dom.each do |dom|
        out, err = @cmd.run!("dig axfr @#{dom[1]} #{dom[2]}")
          if out =~ /Transfer failed|communications error to/i
            @axfr_print << "Zone transfer failed on server: #{dom[1]}/#{dom[0]} for domain #{dom[2]}".upcase.white.on_green
          elsif out =~ /XFR size/i
            @axfr_print << "Zone transfer successful on server: #{dom[1]}/#{dom[0]} for domain #{dom[2]}".upcase.white.on_red
            File.open("#{@axfr_file}", 'a+') { |f| f.puts out }
          else
            @axfr_print << "Unknown response on server: #{dom[1]}/#{dom[0]} for domain #{dom[2]} - Check debug.log".upcase.white.on_green
        end
      end
    end    
  end

end

class Printer

  def initialize(run)
    @run = run
  end
  
  def printns
    if !@run.nsrecords.empty?
    puts "\nNS Records".blue.bold

    splitns = @run.nsrecords.each_slice(2).to_a
      splitns = splitns.uniq { |n| n[0] }
        splitns.each do |n|
          puts n
          puts "#{n[0].join("\t")}\t\t#{n[1].join("\t")}" rescue puts n.join("\t")
        end
      else puts "\nNo Name Servers Found".red
    end
  end

  def printdom
    if @run.domains
    puts "\nDomain Names".blue.bold
    
    splitnames = @run.domains.each_slice(4).to_a
      splitnames.each do |z|
        puts z.join("\t\t") rescue puts z
      end
    end
  end

  def printmx
    if !@run.mxrecords.empty?
    puts "\nMX Records".blue.bold
      
    splitmx = @run.mxrecords.each_slice(2).to_a
      splitmx = splitmx.uniq { |m| m[0] }
        splitmx.each do |m|
          puts "#{m[0].join("\t")}\t\t#{m[1].join("\t")}" rescue puts m.join("\t")
        end
      else puts "\nNo MX Records Found".red
    end
  end

  def printsubs
    if @run.resolved and !@run.resolved.empty?
    puts "\nSub-domains".blue.bold
    
    splitsub = @run.resolved.each_slice(2).to_a
      splitsub.each do |s|
        puts "#{s[0].join("\t")}\t\t#{s[1].join("\t")}" rescue puts s.join("\t")
        end
      else puts "\nNo Subdomains Found/Searched For".red
    end
  end

  def printaxfr
    if !@run.axfr_print.empty?
    puts "\nZone Transfers".blue.bold
    puts @run.axfr_print
    if File.exist?(@run.axfr_file)
      puts "Full transfer output written to axfr_#{@run.time}.txt".upcase.white.on_blue
      end
    end
  end

  def create_file
    Dir.mkdir("#{Dir.home}/Documents/rsdns_out/") unless File.exists?("#{Dir.home}/Documents/rsdns_out/")
    @file    = "rsdns_#{Time.now.strftime("%d%b%Y_%H%M%S")}"
    @csvfile = File.new("#{Dir.home}/Documents/rsdns_out/#{@file}.csv", 'w+')
    puts "Output written to #{@csvfile.path}".light_blue.bold
  end
  
  def output_data
    CSV.open(@csvfile, 'w+') do |csv|
      if @run.domains
        csv << ["DOMAINS"]
          @run.domains.each do |domain|
            csv << [domain]
          end
      end
      if !@run.nsrecords.empty?
        csv << ["\nNAME SERVERS"]
          @run.nsrecords.each do |ns|
            csv << ns
          end
      end
      if !@run.mxrecords.empty?
        csv << ["\nMX RECORDS"]
          @run.mxrecords.each do |mx|
            csv << mx
          end
      end
      if @run.resolved and !@run.resolved.empty?
        csv << ["\nSUBDOMAINS"]
          @run.resolved.each do |subs|
            csv << subs
          end
      end
    end    
  end
 
end

run = Rsdns.new

run.arguments
run.domain
run.domainlist
run.mx
run.ns
run.remove_domain
run.wildcard_test
run.remove_wildcard
run.createsubs
run.subdomains
run.axfr

printme = Printer.new(run)
printme.printdom
printme.printns
printme.printmx
printme.printsubs
printme.printaxfr
printme.create_file
printme.output_data