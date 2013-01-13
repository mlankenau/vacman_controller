require 'rspec'
require 'vacman_controller'

describe "vacman_controller" do
  describe "imort dpx file" do
    it "should import the right number of serials" do
      all = VacmanController.import('sample_dpx/VDP0000000.dpx', "11111111111111111111111111111111")
      all.count.should be 20
    end

    it "should have the serials" do
      all = VacmanController.import('sample_dpx/VDP0000000.dpx', "11111111111111111111111111111111")
      all.select { |e| e['serial'] == "VDP0000000"}.count.should be 1
    end


    it "should fail with a false key" do
      expect {
        VacmanController.import('sample_dpx/VDP0000000.dpx', "00000000000000000000000000000000")
      }.to raise_error
    end
  end

  describe "generate key" do
    it "should create a key if allowed" do
      all = VacmanController.import('sample_dpx/VDP0000000.dpx', "11111111111111111111111111111111")
      first = all.first
      key = VacmanController.generate_password(first)
      key.should match /[0-9]+/
    end
  end

  describe "verify a password" do
    it "should verify a valid key ok" do
      first = VacmanController.import('sample_dpx/VDP0000000.dpx', "11111111111111111111111111111111").first
      key = VacmanController.generate_password first
      VacmanController.verify_password(first, key).should be_true
    end

    it "should NOT verify a invalid key ok" do
      first = VacmanController.import('sample_dpx/VDP0000000.dpx', "11111111111111111111111111111111").first
      key = "111111"
      expect {
        VacmanController.verify_password(first, key)
      }.to raise_error(StandardError, "Validation Failed")
    end

  end

  describe "to many false password attempts will lock the digipass" do
    it "should allow two false password without locking" do
      first = VacmanController.import('sample_dpx/VDP0000000.dpx', "11111111111111111111111111111111").first
      
      2.times do
        expect {VacmanController.verify_password(first, "000000") }.to raise_error(StandardError, "Validation Failed")
      end

      key = VacmanController.generate_password first
      VacmanController.verify_password(first, key).should be_true
    end      
  end


  describe "security" do
    it "should not allow for buffer overflows" do
      first = VacmanController.import('sample_dpx/VDP0000000.dpx', "11111111111111111111111111111111").first
      expect { VacmanController.verify_password(first, "1"*10000) }.to raise_error 
    end
  end


end