package com.spring.codeblog.service;

import com.spring.codeblog.model.Post;

import java.util.List;

public interface CodeblogService {

    List<Post> findAll();

    Post findbyId(long id);

    Post save(Post post);

}
