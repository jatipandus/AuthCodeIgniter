<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->load->library('form_validation');
    }

    public function index()
    {
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email');
        $this->form_validation->set_rules('password', 'Password', 'required');

        if ($this->form_validation->run() == false) {
            $data['title'] = "Login";
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/login');
            $this->load->view('templates/auth_footer');
        } else {
            $this->_login();
        }
    }

    private function _login()
    {
        $email = $this->input->post('email');
        $password = $this->input->post('password');

        $user = $this->db->get_where('user', ['email' => $email])->row_array();

        // var_dump($user);
        // die;

        if ($user) {
            if ($user['is_active'] == 1) {
                if (password_verify($password, $user['password'])) {
                    $data = [
                        'email' => $user['email'],
                        'role_id' => $user['role_id']
                    ];

                    $this->session->set_userdata($data);
                    if ($user['role_id'] == 1) {
                        redirect('admin');
                    } else {
                        redirect('user');
                    }
                } else {
                    $this->session->set_flashdata('message', '
                    <div class="alert alert-danger" role="alert">Wrong Password!</div>');
                    redirect('auth');
                }
            } else {
                $this->session->set_flashdata('message', '
                <div class="alert alert-danger" role="alert">This Account Is Not Active</div>');
                redirect('auth');
            }
        } else {
            $this->session->set_flashdata('message', '
            <div class="alert alert-danger" role="alert">This Account Is Not Registered</div>');
            redirect('auth');
        }
    }

    public function registration()
    {
        $this->form_validation->set_rules('name', 'Name', 'required|trim');
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[user.email]|is_unique[user.email]', [
            'is_unique' => 'This Email Already Registerd'
        ]);
        $this->form_validation->set_rules('password', 'Password', 'required|min_length[2]|matches[confirmPassword]', [
            'matches' => 'Password Not Match',
            'min_length' => 'Password Too Short'
        ]);
        $this->form_validation->set_rules('confirmPassword', 'ConfirmPassword', 'required|matches[password]');

        if ($this->form_validation->run() == false) {
            $data['title'] = "Registration";
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/registration');
            $this->load->view('templates/auth_footer');
        } else {
            $data = [
                'name' => htmlspecialchars($this->input->post('name', true)),
                'email' => htmlspecialchars($this->input->post('email', true)),
                'image' => 'default.png',
                'password' => password_hash($this->input->post('password'), PASSWORD_DEFAULT),
                'role_id' => 2,
                'is_active' => 1,
                'date_created' => time()
            ];

            //input data
            $this->db->insert('user', $data);
            $this->session->set_flashdata('message', '
            <div class="alert alert-success" role="alert">Your Account Is Created</div>');
            redirect('auth');
        }
    }

    public function logout()
    {
        $this->session->unset_userdata('email');
        $this->session->unset_userdata('role_id');

        $this->session->set_flashdata('message', '
            <div class="alert alert-success" role="alert">Logout Success</div>');
        redirect('auth');
    }
}
