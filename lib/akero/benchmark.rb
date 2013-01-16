require 'akero'
require 'gnuplot'
require 'b'

class Akero
  # @private
  class Benchmark
    class << self
      def run!
        b_size
        b_timing
      end

      def b_size
        puts "Running size benchmark..."

        rnd = Random.new
        msg_sizes = (8..14).map{|x| 2**x}
        modes = [[2048, false], [2048, true]]
        results = {}
        modes.each do |mode|
          alice = Akero.new(mode[0])
          bob   = Akero.new(mode[0])
          msg_sizes.each do |msize|
            msg = rnd.bytes(msize)
            ciphertext = alice.encrypt(bob.public_key, msg, mode[1])
            (results["ENCRYPT #{mode[0]} bits #{mode[1] ? 'ascii_armor=1' : 'ascii_armor=0'}"] ||= []) << [msize, ciphertext.length / msg.length.to_f]
          end
        end

        plot('benchmark/bm_size.png', results, 'Message size overhead', 'Input size (bytes)', 'x')
      end

      def b_timing
        puts "Running timing benchmark..."

        msg_sizes = (8..18).map{|x| 2**x}
        modes = [[2048, false], [2048, true]]

        rnd = Random.new

        rounds = 50
        results = []
        modes.each do |mode|
          results << B.enchmark("ENCRYPT #{mode[0]} bits, ascii_armor=#{mode[1]?1:0}", :rounds => rounds, :compare => :mean) do
            alice = Akero.new(mode[0])
            bob   = Akero.new(mode[0])
            msg_sizes.each_with_index do |msize, i|
              msg = rnd.bytes(msize)
              job "msg_size #{msize}" do
                alice.encrypt(bob.public_key, msg, mode[1])
              end
            end
          end
        end

        modes.each do |mode|
          results << B.enchmark("DECRYPT #{mode[0]} bits, ascii_armor=#{mode[1]?1:0}", :rounds => rounds, :compare => :mean) do
            alice = Akero.new(mode[0])
            bob   = Akero.new(mode[0])
            msg_sizes.each_with_index do |msize, i|
              msg = rnd.bytes(msize)
              msg = alice.encrypt(bob.public_key, msg, mode[1])
              job "msg_size #{msize}" do
                bob.receive(msg)
              end
            end
          end
        end

        modes.each do |mode|
          results << B.enchmark("SIGN #{mode[0]} bits, ascii_armor=#{mode[1]?1:0}", :rounds => rounds, :compare => :mean) do
            alice = Akero.new(mode[0])
            bob   = Akero.new(mode[0])
            msg_sizes.each_with_index do |msize, i|
              msg = rnd.bytes(msize)
              job "msg_size #{msize}" do
                alice.sign(msg, mode[1])
              end
            end
          end
        end

        ds = {}
        title = []
        results.each_with_index do |r, i|
          r.each_with_index do |v,j|
            (ds[v[:group]] ||= []) << [msg_sizes[j],v[:rate]]
          end
        end

        plot('benchmark/bm_rate.png', ds, "Throughput", 'Input size (bytes)', 'Messages/sec')
      end

      def plot(path, ds, label, xlabel, ylabel)
        Gnuplot.open do |gp|
          Gnuplot::Plot.new( gp ) do |plot|
            plot.terminal "png"
            plot.output path
            plot.title  label
            plot.xlabel xlabel
            plot.ylabel ylabel
            plot.xtics :axis
            plot.style 'line 1 lc rgb "#8b1a0e" pt 1 ps 1 lt 1 lw 2'
            plot.style 'line 2 lc rgb "#5e9c36" pt 6 ps 1 lt 1 lw 2'
            plot.style 'line 11 lc rgb "#808080" lt 1'
            plot.set 'border 3 back ls 11'
            plot.set 'tics nomirror'
            plot.style 'line 12 lc rgb "#808080" lt 0 lw 1'
            plot.set 'grid back ls 12'
            i=0
            ds.each do |k, v|
              plot.data << Gnuplot::DataSet.new([v.collect {|x| x[0]}, v.collect {|x| x[1]}]) do |_ds|
                _ds.with = "lp ls #{i+1}"
                _ds.title = k
              end
              i+=1
            end
          end
        end
      end
    end
  end
end
